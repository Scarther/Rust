//! # Process Information Security Tool
//!
//! This module demonstrates gathering process information in Rust for security
//! analysis, including:
//! - Current process information (PID, PPID, user, etc.)
//! - System-wide process listing
//! - Memory and CPU usage monitoring
//! - Process tree analysis
//! - Detecting suspicious processes
//!
//! ## Security Use Cases
//! - Detecting malicious processes
//! - Monitoring resource usage anomalies
//! - Identifying privilege escalation attempts
//! - Forensic analysis of running processes

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process;
use sysinfo::{Pid, ProcessStatus, System, Users};
use thiserror::Error;

// ============================================================================
// CUSTOM ERROR TYPES
// ============================================================================

/// Custom error types for process operations
#[derive(Error, Debug)]
pub enum ProcessError {
    /// Error when process is not found
    #[error("Process not found: {0}")]
    NotFound(u32),

    /// Error when permission is denied
    #[error("Permission denied to access process: {0}")]
    PermissionDenied(u32),

    /// Error when system info cannot be retrieved
    #[error("Failed to retrieve system information")]
    SystemInfoError,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents detailed information about a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name
    pub name: String,
    /// Full command line
    pub cmdline: String,
    /// Executable path
    pub exe_path: String,
    /// Working directory
    pub cwd: String,
    /// User ID running the process
    pub uid: u32,
    /// Username running the process
    pub username: String,
    /// Process status
    pub status: String,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// Virtual memory usage in bytes
    pub virtual_memory_bytes: u64,
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// Start time (Unix timestamp)
    pub start_time: u64,
    /// Environment variables (if accessible)
    pub environment: Vec<String>,
}

/// System summary information
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemSummary {
    /// Total number of processes
    pub total_processes: usize,
    /// Total memory in bytes
    pub total_memory: u64,
    /// Used memory in bytes
    pub used_memory: u64,
    /// Total CPU cores
    pub cpu_count: usize,
    /// System uptime in seconds
    pub uptime: u64,
    /// Hostname
    pub hostname: String,
    /// OS name
    pub os_name: String,
    /// OS version
    pub os_version: String,
}

/// Suspicious process indicators
#[derive(Debug)]
pub struct SuspiciousIndicator {
    /// The indicator type
    pub indicator_type: String,
    /// Description of why it's suspicious
    pub description: String,
    /// Severity level (1-10)
    pub severity: u8,
}

// ============================================================================
// CLI ARGUMENT STRUCTURES
// ============================================================================

/// Process Information Tool - Security-focused process analysis
///
/// This tool provides comprehensive process information gathering with
/// security analysis capabilities.
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

/// Available subcommands for process operations
#[derive(Subcommand, Debug)]
enum Commands {
    /// Show current process information
    Self_ {
        /// Show environment variables
        #[arg(short, long)]
        env: bool,
    },

    /// List all running processes
    List {
        /// Filter by process name
        #[arg(short, long)]
        name: Option<String>,

        /// Filter by user
        #[arg(short, long)]
        user: Option<String>,

        /// Sort by field (pid, name, cpu, memory)
        #[arg(short, long, default_value = "pid")]
        sort: String,

        /// Limit output to N processes
        #[arg(short, long)]
        limit: Option<usize>,

        /// Show processes using more than X% CPU
        #[arg(long)]
        high_cpu: Option<f32>,

        /// Show processes using more than X MB memory
        #[arg(long)]
        high_mem: Option<u64>,
    },

    /// Get detailed information about a specific process
    Info {
        /// Process ID to inspect
        pid: u32,

        /// Show environment variables
        #[arg(short, long)]
        env: bool,
    },

    /// Show process tree
    Tree {
        /// Root PID (default: 1 or init)
        #[arg(short, long)]
        root: Option<u32>,

        /// Maximum depth to display
        #[arg(short, long, default_value = "5")]
        depth: usize,
    },

    /// Show system summary
    System,

    /// Analyze processes for suspicious activity
    Audit {
        /// Only show findings with severity >= this level
        #[arg(short, long, default_value = "1")]
        min_severity: u8,
    },

    /// Find process by name pattern
    Find {
        /// Pattern to search for
        pattern: String,

        /// Case insensitive search
        #[arg(short, long)]
        ignore_case: bool,
    },

    /// Monitor a process in real-time
    Monitor {
        /// Process ID to monitor
        pid: u32,

        /// Update interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,

        /// Number of updates (0 = infinite)
        #[arg(short, long, default_value = "10")]
        count: u32,
    },
}

// ============================================================================
// SYSTEM INFORMATION FUNCTIONS
// ============================================================================

/// Creates a new System instance with process information refreshed
///
/// # Returns
/// * `System` - Initialized system information object
fn create_system() -> System {
    let mut sys = System::new_all();
    // Refresh twice to get accurate CPU usage
    sys.refresh_all();
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_all();
    sys
}

/// Gets the current process information
///
/// # Returns
/// * `Result<ProcessInfo>` - Current process info or error
fn get_current_process_info(show_env: bool) -> Result<ProcessInfo> {
    let sys = create_system();
    let current_pid = process::id();

    get_process_info(&sys, current_pid, show_env)
}

/// Gets detailed information about a specific process
///
/// # Arguments
/// * `sys` - System information object
/// * `pid` - Process ID to query
/// * `include_env` - Whether to include environment variables
///
/// # Returns
/// * `Result<ProcessInfo>` - Process info or error
fn get_process_info(sys: &System, pid: u32, include_env: bool) -> Result<ProcessInfo> {
    let sysinfo_pid = Pid::from_u32(pid);

    let process = sys
        .process(sysinfo_pid)
        .ok_or_else(|| ProcessError::NotFound(pid))?;

    // Get user information
    let users = Users::new_with_refreshed_list();
    let uid = process.user_id().map(|u| **u).unwrap_or(0);
    let username = users
        .iter()
        .find(|u| *u.id() == uid)
        .map(|u| u.name().to_string())
        .unwrap_or_else(|| format!("uid:{}", uid));

    // Get parent PID
    let ppid = process
        .parent()
        .map(|p| p.as_u32())
        .unwrap_or(0);

    // Get environment variables if requested
    let environment = if include_env {
        process.environ().iter().map(|s| s.to_string_lossy().to_string()).collect()
    } else {
        Vec::new()
    };

    // Build the process info struct
    Ok(ProcessInfo {
        pid,
        ppid,
        name: process.name().to_string_lossy().to_string(),
        cmdline: process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" "),
        exe_path: process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        cwd: process
            .cwd()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        uid,
        username,
        status: format!("{:?}", process.status()),
        memory_bytes: process.memory(),
        virtual_memory_bytes: process.virtual_memory(),
        cpu_percent: process.cpu_usage(),
        start_time: process.start_time(),
        environment,
    })
}

/// Gets system summary information
///
/// # Returns
/// * `SystemSummary` - System summary data
fn get_system_summary(sys: &System) -> SystemSummary {
    SystemSummary {
        total_processes: sys.processes().len(),
        total_memory: sys.total_memory(),
        used_memory: sys.used_memory(),
        cpu_count: sys.cpus().len(),
        uptime: System::uptime(),
        hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
        os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
    }
}

// ============================================================================
// PROCESS LISTING AND FILTERING
// ============================================================================

/// Lists all processes with optional filtering
///
/// # Arguments
/// * `name_filter` - Optional name filter
/// * `user_filter` - Optional user filter
/// * `sort_by` - Field to sort by
/// * `limit` - Maximum number of processes to return
/// * `high_cpu` - Minimum CPU threshold
/// * `high_mem` - Minimum memory threshold (MB)
///
/// # Returns
/// * `Vec<ProcessInfo>` - List of matching processes
fn list_processes(
    name_filter: Option<&str>,
    user_filter: Option<&str>,
    sort_by: &str,
    limit: Option<usize>,
    high_cpu: Option<f32>,
    high_mem: Option<u64>,
) -> Vec<ProcessInfo> {
    let sys = create_system();
    let users = Users::new_with_refreshed_list();

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let uid = process.user_id().map(|u| **u).unwrap_or(0);
            let username = users
                .iter()
                .find(|u| *u.id() == uid)
                .map(|u| u.name().to_string())
                .unwrap_or_else(|| format!("uid:{}", uid));

            let name = process.name().to_string_lossy().to_string();

            // Apply name filter
            if let Some(filter) = name_filter {
                if !name.to_lowercase().contains(&filter.to_lowercase()) {
                    return None;
                }
            }

            // Apply user filter
            if let Some(filter) = user_filter {
                if !username.to_lowercase().contains(&filter.to_lowercase()) {
                    return None;
                }
            }

            // Apply CPU threshold
            if let Some(threshold) = high_cpu {
                if process.cpu_usage() < threshold {
                    return None;
                }
            }

            // Apply memory threshold (convert MB to bytes)
            if let Some(threshold) = high_mem {
                if process.memory() < threshold * 1024 * 1024 {
                    return None;
                }
            }

            let ppid = process.parent().map(|p| p.as_u32()).unwrap_or(0);

            Some(ProcessInfo {
                pid: pid.as_u32(),
                ppid,
                name,
                cmdline: process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" "),
                exe_path: process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                cwd: process.cwd().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                uid,
                username,
                status: format!("{:?}", process.status()),
                memory_bytes: process.memory(),
                virtual_memory_bytes: process.virtual_memory(),
                cpu_percent: process.cpu_usage(),
                start_time: process.start_time(),
                environment: Vec::new(),
            })
        })
        .collect();

    // Sort processes
    match sort_by {
        "name" => processes.sort_by(|a, b| a.name.cmp(&b.name)),
        "cpu" => processes.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap()),
        "memory" => processes.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
        _ => processes.sort_by_key(|p| p.pid),
    }

    // Apply limit
    if let Some(limit) = limit {
        processes.truncate(limit);
    }

    processes
}

// ============================================================================
// PROCESS TREE FUNCTIONS
// ============================================================================

/// Builds and displays a process tree
///
/// # Arguments
/// * `root_pid` - The root PID to start from
/// * `max_depth` - Maximum depth to display
fn display_process_tree(root_pid: Option<u32>, max_depth: usize) {
    let sys = create_system();

    // Build parent-child relationships
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, process) in sys.processes() {
        let ppid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
        children.entry(ppid).or_default().push(pid.as_u32());
    }

    // Find root processes
    let roots: Vec<u32> = if let Some(pid) = root_pid {
        vec![pid]
    } else {
        // Find processes with no parent or parent = 0
        sys.processes()
            .iter()
            .filter(|(_, p)| p.parent().is_none() || p.parent().map(|pp| pp.as_u32()) == Some(0))
            .map(|(pid, _)| pid.as_u32())
            .collect()
    };

    println!("\n{}", "Process Tree".bold().underline());

    for root in roots {
        print_tree_node(&sys, root, &children, 0, max_depth, "");
    }
}

/// Recursively prints a tree node
fn print_tree_node(
    sys: &System,
    pid: u32,
    children: &HashMap<u32, Vec<u32>>,
    depth: usize,
    max_depth: usize,
    prefix: &str,
) {
    if depth > max_depth {
        return;
    }

    let sysinfo_pid = Pid::from_u32(pid);
    let process = sys.process(sysinfo_pid);

    let name = process
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| "?".to_string());

    let cpu = process.map(|p| p.cpu_usage()).unwrap_or(0.0);
    let mem = process.map(|p| p.memory()).unwrap_or(0) / 1024 / 1024;

    println!(
        "{}{} {} (CPU: {:.1}%, MEM: {} MB)",
        prefix,
        pid.to_string().cyan(),
        name.bold(),
        cpu,
        mem
    );

    if let Some(child_pids) = children.get(&pid) {
        let child_count = child_pids.len();
        for (i, &child_pid) in child_pids.iter().enumerate() {
            let is_last = i == child_count - 1;
            let new_prefix = if depth == 0 {
                if is_last { "  └─ " } else { "  ├─ " }
            } else {
                &format!("{}{}",
                    prefix.replace("├─ ", "│  ").replace("└─ ", "   "),
                    if is_last { "  └─ " } else { "  ├─ " }
                )
            };
            print_tree_node(sys, child_pid, children, depth + 1, max_depth, new_prefix);
        }
    }
}

// ============================================================================
// SECURITY AUDIT FUNCTIONS
// ============================================================================

/// Known suspicious process names or patterns
const SUSPICIOUS_NAMES: &[&str] = &[
    "nc", "ncat", "netcat",
    "nmap",
    "tcpdump",
    "wireshark",
    "msfconsole", "msfvenom", "meterpreter",
    "hydra",
    "john",
    "hashcat",
    "mimikatz",
    "pwdump",
    "procdump",
    "lazagne",
    "crackmapexec",
    "bloodhound",
    "evil-winrm",
    "chisel",
    "socat",
];

/// Audits all processes for suspicious activity
///
/// # Arguments
/// * `min_severity` - Minimum severity level to report
///
/// # Returns
/// * `Vec<(ProcessInfo, Vec<SuspiciousIndicator>)>` - Suspicious processes and their indicators
fn audit_processes(min_severity: u8) -> Vec<(ProcessInfo, Vec<SuspiciousIndicator>)> {
    let sys = create_system();
    let mut results = Vec::new();

    for (pid, process) in sys.processes() {
        let mut indicators = Vec::new();
        let name = process.name().to_string_lossy().to_lowercase();
        let cmdline = process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" ");
        let exe_path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

        // Check for known suspicious process names
        for suspicious in SUSPICIOUS_NAMES {
            if name.contains(suspicious) {
                indicators.push(SuspiciousIndicator {
                    indicator_type: "known_tool".to_string(),
                    description: format!("Process matches known security/hacking tool: {}", suspicious),
                    severity: 7,
                });
            }
        }

        // Check for deleted executables (common malware behavior)
        if exe_path.contains("(deleted)") {
            indicators.push(SuspiciousIndicator {
                indicator_type: "deleted_exe".to_string(),
                description: "Executable has been deleted while process is running".to_string(),
                severity: 9,
            });
        }

        // Check for processes in temp directories
        if exe_path.contains("/tmp/") || exe_path.contains("/var/tmp/") {
            indicators.push(SuspiciousIndicator {
                indicator_type: "temp_execution".to_string(),
                description: "Process running from temporary directory".to_string(),
                severity: 6,
            });
        }

        // Check for hidden directories in path
        if exe_path.contains("/.") && !exe_path.contains("/.local") {
            indicators.push(SuspiciousIndicator {
                indicator_type: "hidden_directory".to_string(),
                description: "Process running from hidden directory".to_string(),
                severity: 5,
            });
        }

        // Check for base64 in command line (common obfuscation)
        if cmdline.to_lowercase().contains("base64") {
            indicators.push(SuspiciousIndicator {
                indicator_type: "base64_usage".to_string(),
                description: "Command line contains base64 (possible obfuscation)".to_string(),
                severity: 4,
            });
        }

        // Check for reverse shell patterns
        let shell_patterns = ["/dev/tcp", "/dev/udp", "bash -i", "sh -i", "0>&1", ">&2"];
        for pattern in shell_patterns {
            if cmdline.contains(pattern) {
                indicators.push(SuspiciousIndicator {
                    indicator_type: "reverse_shell".to_string(),
                    description: format!("Possible reverse shell pattern: {}", pattern),
                    severity: 10,
                });
            }
        }

        // Check for high CPU usage
        if process.cpu_usage() > 90.0 {
            indicators.push(SuspiciousIndicator {
                indicator_type: "high_cpu".to_string(),
                description: format!("Very high CPU usage: {:.1}%", process.cpu_usage()),
                severity: 3,
            });
        }

        // Check for processes running as root but not system processes
        let uid = process.user_id().map(|u| **u).unwrap_or(u32::MAX);
        if uid == 0 {
            let system_processes = ["systemd", "init", "kthreadd", "kworker", "ksoftirqd"];
            if !system_processes.iter().any(|sp| name.contains(sp)) {
                indicators.push(SuspiciousIndicator {
                    indicator_type: "root_process".to_string(),
                    description: "Non-system process running as root".to_string(),
                    severity: 4,
                });
            }
        }

        // Filter by minimum severity and collect results
        let filtered_indicators: Vec<_> = indicators
            .into_iter()
            .filter(|i| i.severity >= min_severity)
            .collect();

        if !filtered_indicators.is_empty() {
            if let Ok(info) = get_process_info(&sys, pid.as_u32(), false) {
                results.push((info, filtered_indicators));
            }
        }
    }

    // Sort by highest severity indicator
    results.sort_by(|a, b| {
        let max_a = a.1.iter().map(|i| i.severity).max().unwrap_or(0);
        let max_b = b.1.iter().map(|i| i.severity).max().unwrap_or(0);
        max_b.cmp(&max_a)
    });

    results
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

/// Formats bytes into human-readable format
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
        format!("{} B", bytes)
    }
}

/// Displays process information in a formatted way
fn display_process_info(info: &ProcessInfo, show_env: bool) {
    println!("\n{}", "Process Information".bold().underline());
    println!("PID:              {}", info.pid.to_string().cyan());
    println!("Parent PID:       {}", info.ppid);
    println!("Name:             {}", info.name.bold());
    println!("Command:          {}", info.cmdline);
    println!("Executable:       {}", info.exe_path);
    println!("Working Dir:      {}", info.cwd);
    println!("User:             {} (UID: {})", info.username.green(), info.uid);
    println!("Status:           {}", info.status);
    println!("Memory:           {}", format_bytes(info.memory_bytes));
    println!("Virtual Memory:   {}", format_bytes(info.virtual_memory_bytes));
    println!("CPU Usage:        {:.2}%", info.cpu_percent);
    println!("Start Time:       {} (Unix timestamp)", info.start_time);

    if show_env && !info.environment.is_empty() {
        println!("\n{}", "Environment Variables:".yellow());
        for env_var in &info.environment {
            // Mask potentially sensitive values
            if env_var.to_uppercase().contains("KEY")
                || env_var.to_uppercase().contains("SECRET")
                || env_var.to_uppercase().contains("PASSWORD")
            {
                let parts: Vec<&str> = env_var.splitn(2, '=').collect();
                if parts.len() == 2 {
                    println!("  {}=***MASKED***", parts[0]);
                } else {
                    println!("  {}", env_var);
                }
            } else {
                println!("  {}", env_var);
            }
        }
    }
}

/// Displays system summary
fn display_system_summary(summary: &SystemSummary) {
    println!("\n{}", "System Summary".bold().underline());
    println!("Hostname:         {}", summary.hostname.cyan());
    println!("OS:               {} {}", summary.os_name, summary.os_version);
    println!("CPU Cores:        {}", summary.cpu_count);
    println!("Uptime:           {} seconds ({:.1} hours)",
             summary.uptime,
             summary.uptime as f64 / 3600.0);
    println!("Total Memory:     {}", format_bytes(summary.total_memory));
    println!("Used Memory:      {} ({:.1}%)",
             format_bytes(summary.used_memory),
             (summary.used_memory as f64 / summary.total_memory as f64) * 100.0);
    println!("Total Processes:  {}", summary.total_processes);
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Self_ { env } => {
            let info = get_current_process_info(env)?;
            display_process_info(&info, env);
        }

        Commands::List {
            name,
            user,
            sort,
            limit,
            high_cpu,
            high_mem,
        } => {
            let processes = list_processes(
                name.as_deref(),
                user.as_deref(),
                &sort,
                limit,
                high_cpu,
                high_mem,
            );

            println!("\n{}", "Process List".bold().underline());
            println!(
                "{:>7} {:>7} {:>6} {:>10} {:>6} {:<20} {}",
                "PID", "PPID", "CPU%", "MEMORY", "STATUS", "USER", "NAME"
            );
            println!("{}", "-".repeat(80));

            for proc in &processes {
                let status_short = match proc.status.as_str() {
                    "Run" => "R".green(),
                    "Sleep" => "S".normal(),
                    "Stop" => "T".yellow(),
                    "Zombie" => "Z".red(),
                    _ => proc.status.chars().next().unwrap_or('?').to_string().normal(),
                };

                println!(
                    "{:>7} {:>7} {:>5.1}% {:>10} {:>6} {:<20} {}",
                    proc.pid.to_string().cyan(),
                    proc.ppid,
                    proc.cpu_percent,
                    format_bytes(proc.memory_bytes),
                    status_short,
                    proc.username.green(),
                    proc.name.bold()
                );
            }

            println!("\nTotal: {} processes", processes.len());
        }

        Commands::Info { pid, env } => {
            let sys = create_system();
            let info = get_process_info(&sys, pid, env)?;
            display_process_info(&info, env);
        }

        Commands::Tree { root, depth } => {
            display_process_tree(root, depth);
        }

        Commands::System => {
            let sys = create_system();
            let summary = get_system_summary(&sys);
            display_system_summary(&summary);
        }

        Commands::Audit { min_severity } => {
            let results = audit_processes(min_severity);

            println!("\n{}", "Security Audit Results".bold().underline());
            println!("Minimum severity: {}", min_severity);
            println!("Suspicious processes found: {}\n", results.len());

            if results.is_empty() {
                println!("{} No suspicious processes detected", "OK:".green());
            } else {
                for (proc, indicators) in &results {
                    println!("{} {} (PID: {})", ">>>".red(), proc.name.bold(), proc.pid);
                    println!("    Command: {}", proc.cmdline.dimmed());
                    println!("    User: {} | Exe: {}", proc.username, proc.exe_path);

                    for indicator in indicators {
                        let severity_color = match indicator.severity {
                            1..=3 => indicator.severity.to_string().blue(),
                            4..=6 => indicator.severity.to_string().yellow(),
                            7..=8 => indicator.severity.to_string().red(),
                            _ => indicator.severity.to_string().red().bold(),
                        };

                        println!(
                            "    [Severity: {}] {}: {}",
                            severity_color,
                            indicator.indicator_type.cyan(),
                            indicator.description
                        );
                    }
                    println!();
                }
            }
        }

        Commands::Find { pattern, ignore_case } => {
            let sys = create_system();
            let pattern_lower = if ignore_case {
                pattern.to_lowercase()
            } else {
                pattern.clone()
            };

            println!("\n{}", format!("Searching for: {}", pattern).bold().underline());

            let matches: Vec<_> = sys
                .processes()
                .iter()
                .filter(|(_, p)| {
                    let name = p.name().to_string_lossy();
                    let name_cmp = if ignore_case {
                        name.to_lowercase()
                    } else {
                        name.to_string()
                    };
                    name_cmp.contains(&pattern_lower)
                })
                .collect();

            if matches.is_empty() {
                println!("No processes found matching '{}'", pattern);
            } else {
                println!("Found {} matching processes:\n", matches.len());
                for (pid, process) in matches {
                    println!(
                        "  {} {} ({})",
                        pid.as_u32().to_string().cyan(),
                        process.name().to_string_lossy().bold(),
                        process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" ").dimmed()
                    );
                }
            }
        }

        Commands::Monitor { pid, interval, count } => {
            let iterations = if count == 0 { u32::MAX } else { count };

            println!("{}", format!("Monitoring PID {} (Ctrl+C to stop)", pid).bold());
            println!();

            for i in 0..iterations {
                let sys = create_system();
                let info = get_process_info(&sys, pid, false);

                match info {
                    Ok(info) => {
                        // Clear previous line (simple approach)
                        print!("\r{}", " ".repeat(80));
                        print!(
                            "\r[{:>4}] CPU: {:>5.1}% | MEM: {:>10} | Status: {}",
                            i + 1,
                            info.cpu_percent,
                            format_bytes(info.memory_bytes),
                            info.status
                        );
                        std::io::Write::flush(&mut std::io::stdout())?;
                    }
                    Err(_) => {
                        println!("\n{} Process {} no longer exists", "Error:".red(), pid);
                        break;
                    }
                }

                if i < iterations - 1 {
                    std::thread::sleep(std::time::Duration::from_secs(interval));
                }
            }
            println!();
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

    #[test]
    fn test_create_system() {
        let sys = create_system();
        assert!(sys.processes().len() > 0);
    }

    #[test]
    fn test_get_current_process() {
        let info = get_current_process_info(false);
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.pid, process::id());
    }

    #[test]
    fn test_system_summary() {
        let sys = create_system();
        let summary = get_system_summary(&sys);
        assert!(summary.total_processes > 0);
        assert!(summary.total_memory > 0);
        assert!(summary.cpu_count > 0);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_list_processes() {
        let processes = list_processes(None, None, "pid", Some(10), None, None);
        assert!(!processes.is_empty());
        assert!(processes.len() <= 10);
    }

    #[test]
    fn test_audit_processes() {
        // This should run without error, results depend on running processes
        let results = audit_processes(10); // High threshold to reduce noise
        // Just ensure it doesn't crash
        assert!(results.len() >= 0);
    }

    #[test]
    fn test_process_not_found() {
        let sys = create_system();
        // Use an unlikely PID
        let result = get_process_info(&sys, 999999999, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_suspicious_indicator() {
        let indicator = SuspiciousIndicator {
            indicator_type: "test".to_string(),
            description: "Test indicator".to_string(),
            severity: 5,
        };
        assert_eq!(indicator.severity, 5);
    }
}
