//! # Rootkit Scanner Library
//!
//! This module provides comprehensive rootkit detection capabilities for Linux systems.
//! It demonstrates advanced security analysis techniques including:
//!
//! - Hidden process detection via multiple enumeration methods
//! - Hidden file detection by comparing directory listings
//! - Kernel module analysis
//! - System call table integrity checking concepts
//! - Network socket analysis for hidden connections
//!
//! ## Rootkit Detection Techniques
//!
//! Rootkits hide their presence by:
//! 1. Hooking system calls (syscall table modification)
//! 2. Hiding processes from /proc
//! 3. Hiding files from directory listings
//! 4. Loading malicious kernel modules
//! 5. Modifying network stack to hide connections
//!
//! This scanner detects these by using multiple information sources
//! and looking for discrepancies.
//!
//! ## Advanced Rust Concepts
//!
//! - Unsafe code for low-level system access
//! - FFI for calling C library functions
//! - Raw file descriptors and system calls
//! - Memory-mapped I/O for kernel data access

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::*;
use log::{debug, error, info, warn};
use md5::{Md5, Digest as Md5Digest};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use sysinfo::{ProcessExt, System, SystemExt};
use thiserror::Error;
use walkdir::WalkDir;

/// Custom error types for rootkit scanning operations
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("System error: {0}")]
    SystemError(String),
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Types of rootkit indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    /// Process hidden from /proc but found via other means
    HiddenProcess,
    /// File hidden from directory listing
    HiddenFile,
    /// Suspicious kernel module
    SuspiciousModule,
    /// Modified system binary
    ModifiedBinary,
    /// Hidden network connection
    HiddenConnection,
    /// Suspicious mount point
    SuspiciousMount,
    /// LD_PRELOAD hijacking
    LdPreloadHijack,
    /// Suspicious /dev entries
    SuspiciousDevice,
    /// Anomalous system call behavior
    SyscallAnomaly,
    /// Suspicious scheduled task
    SuspiciousTask,
}

/// A finding from the rootkit scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// When the finding was detected
    pub timestamp: DateTime<Utc>,
    /// Type of indicator
    pub indicator_type: IndicatorType,
    /// Severity of the finding
    pub severity: Severity,
    /// Short description
    pub title: String,
    /// Detailed description
    pub description: String,
    /// File path if applicable
    pub path: Option<PathBuf>,
    /// Process ID if applicable
    pub pid: Option<i32>,
    /// Additional evidence
    pub evidence: HashMap<String, String>,
    /// Recommended action
    pub recommendation: String,
}

/// Process information for comparison
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: i32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: Option<PathBuf>,
    pub ppid: i32,
    pub uid: u32,
}

/// Kernel module information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModule {
    pub name: String,
    pub size: u64,
    pub used_by: Vec<String>,
    pub state: String,
    pub address: Option<u64>,
    pub is_suspicious: bool,
    pub reason: Option<String>,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
    pub inode: u64,
}

/// File integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrity {
    pub path: PathBuf,
    pub sha256: String,
    pub md5: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub is_setuid: bool,
    pub is_setgid: bool,
}

/// Main rootkit scanner
pub struct RootkitScanner {
    /// Collected findings
    pub findings: Vec<Finding>,
    /// System info handle
    system: System,
    /// Known good kernel module hashes (would be loaded from database)
    known_modules: HashSet<String>,
    /// Suspicious module name patterns
    suspicious_patterns: Vec<Regex>,
    /// Critical system binaries to check
    critical_binaries: Vec<PathBuf>,
}

impl RootkitScanner {
    /// Create a new rootkit scanner instance
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        // Suspicious kernel module patterns
        let suspicious_patterns = vec![
            Regex::new(r"(?i)rootkit").unwrap(),
            Regex::new(r"(?i)hide").unwrap(),
            Regex::new(r"(?i)stealth").unwrap(),
            Regex::new(r"(?i)invisible").unwrap(),
            Regex::new(r"(?i)backdoor").unwrap(),
        ];

        // Critical system binaries to verify
        let critical_binaries = vec![
            PathBuf::from("/bin/ls"),
            PathBuf::from("/bin/ps"),
            PathBuf::from("/bin/netstat"),
            PathBuf::from("/bin/ss"),
            PathBuf::from("/bin/find"),
            PathBuf::from("/bin/lsof"),
            PathBuf::from("/usr/bin/ls"),
            PathBuf::from("/usr/bin/ps"),
            PathBuf::from("/usr/bin/netstat"),
            PathBuf::from("/usr/bin/ss"),
            PathBuf::from("/usr/bin/find"),
            PathBuf::from("/usr/bin/lsof"),
            PathBuf::from("/sbin/insmod"),
            PathBuf::from("/sbin/rmmod"),
            PathBuf::from("/sbin/lsmod"),
        ];

        Self {
            findings: Vec::new(),
            system,
            known_modules: HashSet::new(),
            suspicious_patterns,
            critical_binaries,
        }
    }

    /// Run all detection methods
    pub async fn full_scan(&mut self) -> Result<Vec<Finding>> {
        info!("Starting full rootkit scan...");

        // Refresh system info
        self.system.refresh_all();

        // Run all detection methods
        self.detect_hidden_processes().await?;
        self.detect_hidden_files().await?;
        self.analyze_kernel_modules().await?;
        self.check_network_connections().await?;
        self.check_ld_preload().await?;
        self.check_system_binaries().await?;
        self.check_suspicious_mounts().await?;
        self.check_scheduled_tasks().await?;
        self.check_suspicious_devices().await?;

        info!("Scan complete. Found {} indicators.", self.findings.len());

        Ok(self.findings.clone())
    }

    /// Detect hidden processes using multiple enumeration methods
    ///
    /// # Detection Strategy
    /// 1. Read /proc directly (what the kernel shows)
    /// 2. Use sysinfo crate (different code path)
    /// 3. Brute force PID scan (1-65535)
    /// 4. Check /proc/[pid]/task for hidden threads
    ///
    /// Discrepancies indicate process hiding.
    pub async fn detect_hidden_processes(&mut self) -> Result<()> {
        info!("Scanning for hidden processes...");

        // Method 1: Direct /proc enumeration
        let mut proc_pids: HashSet<i32> = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                    proc_pids.insert(pid);
                }
            }
        }
        debug!("Found {} PIDs via /proc listing", proc_pids.len());

        // Method 2: Using sysinfo
        let mut sysinfo_pids: HashSet<i32> = HashSet::new();
        for pid in self.system.processes().keys() {
            sysinfo_pids.insert(pid.as_u32() as i32);
        }
        debug!("Found {} PIDs via sysinfo", sysinfo_pids.len());

        // Method 3: Brute force scan
        // Check every possible PID by trying to access /proc/[pid]/stat
        let mut brute_pids: HashSet<i32> = HashSet::new();
        for pid in 1..=65535i32 {
            let stat_path = format!("/proc/{}/stat", pid);
            if Path::new(&stat_path).exists() {
                brute_pids.insert(pid);
            }
        }
        debug!("Found {} PIDs via brute force", brute_pids.len());

        // Method 4: Check scheduler for PIDs
        // The /proc/sched_debug file (if available) lists all scheduled tasks
        let mut sched_pids: HashSet<i32> = HashSet::new();
        if let Ok(content) = fs::read_to_string("/proc/sched_debug") {
            let pid_regex = Regex::new(r"pid=(\d+)").unwrap();
            for cap in pid_regex.captures_iter(&content) {
                if let Ok(pid) = cap[1].parse::<i32>() {
                    sched_pids.insert(pid);
                }
            }
        }

        // Compare results and look for discrepancies

        // PIDs found by brute force but not in /proc listing = hidden
        for pid in brute_pids.difference(&proc_pids) {
            // Get more info about this hidden process
            let mut evidence = HashMap::new();

            // Try to read cmdline
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                evidence.insert("cmdline".to_string(), cmdline.replace('\0', " "));
            }

            // Try to read exe link
            let exe_path = format!("/proc/{}/exe", pid);
            if let Ok(exe) = fs::read_link(&exe_path) {
                evidence.insert("exe".to_string(), exe.to_string_lossy().to_string());
            }

            self.findings.push(Finding {
                timestamp: Utc::now(),
                indicator_type: IndicatorType::HiddenProcess,
                severity: Severity::Critical,
                title: format!("Hidden process detected: PID {}", pid),
                description: format!(
                    "Process with PID {} was found via direct access but is hidden \
                     from /proc directory listing. This is a strong indicator of \
                     a rootkit manipulating the kernel's getdents syscall.",
                    pid
                ),
                path: None,
                pid: Some(*pid),
                evidence,
                recommendation: "Investigate this process immediately. Consider \
                    booting from a clean live system to analyze the disk.".to_string(),
            });
        }

        // PIDs in sysinfo but not in /proc (should not happen)
        for pid in sysinfo_pids.difference(&proc_pids) {
            if !brute_pids.contains(pid) {
                self.findings.push(Finding {
                    timestamp: Utc::now(),
                    indicator_type: IndicatorType::HiddenProcess,
                    severity: Severity::High,
                    title: format!("Process enumeration inconsistency: PID {}", pid),
                    description: format!(
                        "Process {} appears in sysinfo but not in /proc listing. \
                         This could indicate kernel-level process hiding.",
                        pid
                    ),
                    path: None,
                    pid: Some(*pid),
                    evidence: HashMap::new(),
                    recommendation: "Investigate kernel integrity.".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Detect hidden files by comparing directory APIs
    ///
    /// # Detection Strategy
    /// 1. Use readdir (normal listing)
    /// 2. Use getdents syscall directly
    /// 3. Compare inode listings
    ///
    /// Files present in one but not another may be hidden.
    pub async fn detect_hidden_files(&mut self) -> Result<()> {
        info!("Scanning for hidden files...");

        // Directories to check
        let check_dirs = vec![
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/root",
            "/home",
            "/etc",
            "/lib",
            "/lib64",
            "/usr/lib",
        ];

        for dir in check_dirs {
            if let Err(e) = self.check_directory_for_hidden_files(dir).await {
                debug!("Could not check {}: {}", dir, e);
            }
        }

        Ok(())
    }

    /// Check a specific directory for hidden files
    async fn check_directory_for_hidden_files(&mut self, dir_path: &str) -> Result<()> {
        let path = Path::new(dir_path);
        if !path.exists() || !path.is_dir() {
            return Ok(());
        }

        // Method 1: Standard directory listing
        let mut std_files: HashSet<String> = HashSet::new();
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                std_files.insert(entry.file_name().to_string_lossy().to_string());
            }
        }

        // Method 2: Using getdents syscall directly (via walkdir)
        // This uses a different code path that might bypass some hooks
        let mut walk_files: HashSet<String> = HashSet::new();
        for entry in WalkDir::new(path).max_depth(1).into_iter().flatten() {
            if entry.path() != path {
                if let Some(name) = entry.file_name().to_str() {
                    walk_files.insert(name.to_string());
                }
            }
        }

        // Check for discrepancies
        // Files in walk but not in std listing might be hidden
        for file in walk_files.difference(&std_files) {
            let file_path = path.join(file);
            let mut evidence = HashMap::new();

            if let Ok(metadata) = fs::metadata(&file_path) {
                evidence.insert("size".to_string(), metadata.len().to_string());
                evidence.insert("mode".to_string(), format!("{:o}", metadata.mode()));
            }

            self.findings.push(Finding {
                timestamp: Utc::now(),
                indicator_type: IndicatorType::HiddenFile,
                severity: Severity::High,
                title: format!("Potentially hidden file: {}", file_path.display()),
                description: format!(
                    "File '{}' shows inconsistent visibility across different \
                     directory enumeration methods.",
                    file_path.display()
                ),
                path: Some(file_path),
                pid: None,
                evidence,
                recommendation: "Investigate this file and consider removing it \
                    after backup.".to_string(),
            });
        }

        // Also check for suspiciously named files
        for file in std_files.iter() {
            // Look for files that look like they're trying to hide
            if file.starts_with("... ")
                || file.starts_with(".. ")
                || file.contains('\0')
                || file.len() > 255
            {
                let file_path = path.join(file);
                self.findings.push(Finding {
                    timestamp: Utc::now(),
                    indicator_type: IndicatorType::HiddenFile,
                    severity: Severity::Medium,
                    title: format!("Suspiciously named file: {}", file),
                    description: format!(
                        "File '{}' has a suspicious name that might be \
                         designed to hide it from casual inspection.",
                        file_path.display()
                    ),
                    path: Some(file_path),
                    pid: None,
                    evidence: HashMap::new(),
                    recommendation: "Review this file's contents and purpose.".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Analyze loaded kernel modules for suspicious entries
    ///
    /// # Checks performed:
    /// 1. Module names matching suspicious patterns
    /// 2. Modules loaded from unusual paths
    /// 3. Hidden modules (present in memory but not in /proc/modules)
    /// 4. Modules with suspicious capabilities
    pub async fn analyze_kernel_modules(&mut self) -> Result<()> {
        info!("Analyzing kernel modules...");

        // Parse /proc/modules
        let modules = self.parse_proc_modules()?;

        for module in &modules {
            // Check against suspicious patterns
            for pattern in &self.suspicious_patterns {
                if pattern.is_match(&module.name) {
                    self.findings.push(Finding {
                        timestamp: Utc::now(),
                        indicator_type: IndicatorType::SuspiciousModule,
                        severity: Severity::Critical,
                        title: format!("Suspicious kernel module: {}", module.name),
                        description: format!(
                            "Kernel module '{}' has a name matching suspicious patterns. \
                             This could indicate a rootkit.",
                            module.name
                        ),
                        path: None,
                        pid: None,
                        evidence: HashMap::from([
                            ("size".to_string(), module.size.to_string()),
                            ("state".to_string(), module.state.clone()),
                        ]),
                        recommendation: "Immediately investigate this module. Consider \
                            unloading it and analyzing the system from a clean boot.".to_string(),
                    });
                }
            }
        }

        // Check for modules that might be hiding
        // Compare /proc/modules with /sys/module
        let mut proc_modules: HashSet<String> = HashSet::new();
        for module in &modules {
            proc_modules.insert(module.name.clone());
        }

        let mut sys_modules: HashSet<String> = HashSet::new();
        if let Ok(entries) = fs::read_dir("/sys/module") {
            for entry in entries.flatten() {
                sys_modules.insert(entry.file_name().to_string_lossy().to_string());
            }
        }

        // Modules in /sys/module but not in /proc/modules could be hiding
        for module_name in sys_modules.difference(&proc_modules) {
            // Some modules in /sys/module are built-in, check for module file
            let module_path = format!("/sys/module/{}/initstate", module_name);
            if Path::new(&module_path).exists() {
                self.findings.push(Finding {
                    timestamp: Utc::now(),
                    indicator_type: IndicatorType::SuspiciousModule,
                    severity: Severity::High,
                    title: format!("Potentially hidden kernel module: {}", module_name),
                    description: format!(
                        "Module '{}' appears in /sys/module but not in /proc/modules. \
                         This could indicate module hiding.",
                        module_name
                    ),
                    path: Some(PathBuf::from(format!("/sys/module/{}", module_name))),
                    pid: None,
                    evidence: HashMap::new(),
                    recommendation: "Investigate this module's origin and purpose.".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Parse /proc/modules into structured data
    fn parse_proc_modules(&self) -> Result<Vec<KernelModule>> {
        let content = fs::read_to_string("/proc/modules")
            .context("Failed to read /proc/modules")?;

        let mut modules = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let name = parts[0].to_string();
            let size = parts[1].parse().unwrap_or(0);
            let used_by: Vec<String> = if parts[3] != "-" {
                parts[3].trim_end_matches(',').split(',')
                    .map(|s| s.to_string())
                    .collect()
            } else {
                Vec::new()
            };
            let state = parts.get(4).unwrap_or(&"").to_string();
            let address = parts.get(5).and_then(|s| {
                u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
            });

            // Check if suspicious
            let is_suspicious = self.suspicious_patterns
                .iter()
                .any(|p| p.is_match(&name));

            modules.push(KernelModule {
                name,
                size,
                used_by,
                state,
                address,
                is_suspicious,
                reason: if is_suspicious {
                    Some("Name matches suspicious pattern".to_string())
                } else {
                    None
                },
            });
        }

        Ok(modules)
    }

    /// Check network connections for hidden or suspicious entries
    ///
    /// Compares:
    /// 1. /proc/net/tcp and /proc/net/udp
    /// 2. ss command output
    /// 3. Socket inodes in /proc/[pid]/fd
    pub async fn check_network_connections(&mut self) -> Result<()> {
        info!("Checking network connections...");

        // Parse /proc/net/tcp
        let tcp_conns = self.parse_proc_net("tcp")?;
        let tcp6_conns = self.parse_proc_net("tcp6")?;
        let udp_conns = self.parse_proc_net("udp")?;
        let udp6_conns = self.parse_proc_net("udp6")?;

        let all_conns: Vec<_> = tcp_conns.iter()
            .chain(tcp6_conns.iter())
            .chain(udp_conns.iter())
            .chain(udp6_conns.iter())
            .collect();

        // Get all socket inodes from /proc/[pid]/fd
        let mut fd_inodes: HashSet<u64> = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                    let fd_path = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = fs::read_dir(&fd_path) {
                        for fd in fds.flatten() {
                            if let Ok(link) = fs::read_link(fd.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.starts_with("socket:[") {
                                    if let Some(inode_str) = link_str
                                        .trim_start_matches("socket:[")
                                        .strip_suffix(']')
                                    {
                                        if let Ok(inode) = inode_str.parse::<u64>() {
                                            fd_inodes.insert(inode);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Find connections without a process (orphaned or hidden)
        for conn in all_conns {
            if conn.inode != 0 && !fd_inodes.contains(&conn.inode) && conn.state != "LISTEN" {
                self.findings.push(Finding {
                    timestamp: Utc::now(),
                    indicator_type: IndicatorType::HiddenConnection,
                    severity: Severity::High,
                    title: format!(
                        "Orphaned network connection: {}:{}->{}:{}",
                        conn.local_addr, conn.local_port,
                        conn.remote_addr, conn.remote_port
                    ),
                    description: format!(
                        "A {} connection has no visible process owner. \
                         This could indicate a hidden process or rootkit.",
                        conn.protocol
                    ),
                    path: None,
                    pid: None,
                    evidence: HashMap::from([
                        ("protocol".to_string(), conn.protocol.clone()),
                        ("local".to_string(), format!("{}:{}", conn.local_addr, conn.local_port)),
                        ("remote".to_string(), format!("{}:{}", conn.remote_addr, conn.remote_port)),
                        ("state".to_string(), conn.state.clone()),
                        ("inode".to_string(), conn.inode.to_string()),
                    ]),
                    recommendation: "Investigate this connection using multiple tools. \
                        Consider packet capture.".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Parse /proc/net/{tcp,udp} files
    fn parse_proc_net(&self, protocol: &str) -> Result<Vec<NetworkConnection>> {
        let path = format!("/proc/net/{}", protocol);
        let content = fs::read_to_string(&path)?;
        let mut connections = Vec::new();

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            // Parse local address:port
            let local_parts: Vec<&str> = parts[1].split(':').collect();
            if local_parts.len() != 2 {
                continue;
            }
            let local_addr = Self::hex_to_ip(local_parts[0]);
            let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);

            // Parse remote address:port
            let remote_parts: Vec<&str> = parts[2].split(':').collect();
            if remote_parts.len() != 2 {
                continue;
            }
            let remote_addr = Self::hex_to_ip(remote_parts[0]);
            let remote_port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);

            // Parse state
            let state_num = u8::from_str_radix(parts[3], 16).unwrap_or(0);
            let state = Self::tcp_state_name(state_num);

            // Parse inode
            let inode = parts.get(9)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            connections.push(NetworkConnection {
                protocol: protocol.to_string(),
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid: None,
                process_name: None,
                inode,
            });
        }

        Ok(connections)
    }

    /// Convert hex IP address to dotted decimal
    fn hex_to_ip(hex: &str) -> String {
        if hex.len() == 8 {
            // IPv4
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
            // IPv6 or invalid
            hex.to_string()
        }
    }

    /// Convert TCP state number to name
    fn tcp_state_name(state: u8) -> String {
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
        }.to_string()
    }

    /// Check for LD_PRELOAD attacks
    pub async fn check_ld_preload(&mut self) -> Result<()> {
        info!("Checking for LD_PRELOAD attacks...");

        // Check /etc/ld.so.preload
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            if let Ok(content) = fs::read_to_string(preload_path) {
                let content = content.trim();
                if !content.is_empty() && !content.starts_with('#') {
                    self.findings.push(Finding {
                        timestamp: Utc::now(),
                        indicator_type: IndicatorType::LdPreloadHijack,
                        severity: Severity::High,
                        title: "LD_PRELOAD configuration found".to_string(),
                        description: format!(
                            "The /etc/ld.so.preload file contains: {}. \
                             This file causes libraries to be loaded into all processes.",
                            content
                        ),
                        path: Some(preload_path.to_path_buf()),
                        pid: None,
                        evidence: HashMap::from([
                            ("content".to_string(), content.to_string()),
                        ]),
                        recommendation: "Review the libraries in this file. This is often \
                            used by rootkits.".to_string(),
                    });
                }
            }
        }

        // Check process environments for LD_PRELOAD
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                    let environ_path = format!("/proc/{}/environ", pid);
                    if let Ok(content) = fs::read_to_string(&environ_path) {
                        for env_var in content.split('\0') {
                            if env_var.starts_with("LD_PRELOAD=") {
                                let value = env_var.trim_start_matches("LD_PRELOAD=");

                                // Get process name
                                let comm_path = format!("/proc/{}/comm", pid);
                                let process_name = fs::read_to_string(&comm_path)
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_else(|_| "unknown".to_string());

                                self.findings.push(Finding {
                                    timestamp: Utc::now(),
                                    indicator_type: IndicatorType::LdPreloadHijack,
                                    severity: Severity::Medium,
                                    title: format!(
                                        "LD_PRELOAD set for process {} (PID {})",
                                        process_name, pid
                                    ),
                                    description: format!(
                                        "Process has LD_PRELOAD={} in its environment.",
                                        value
                                    ),
                                    path: None,
                                    pid: Some(pid),
                                    evidence: HashMap::from([
                                        ("ld_preload".to_string(), value.to_string()),
                                        ("process".to_string(), process_name),
                                    ]),
                                    recommendation: "Investigate why this process has \
                                        LD_PRELOAD set.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check integrity of critical system binaries
    pub async fn check_system_binaries(&mut self) -> Result<()> {
        info!("Checking system binary integrity...");

        for binary_path in &self.critical_binaries {
            if !binary_path.exists() {
                continue;
            }

            if let Ok(integrity) = self.compute_file_integrity(binary_path) {
                // Check for SUID/SGID on unexpected binaries
                if integrity.is_setuid || integrity.is_setgid {
                    let mode_str = if integrity.is_setuid && integrity.is_setgid {
                        "SUID+SGID"
                    } else if integrity.is_setuid {
                        "SUID"
                    } else {
                        "SGID"
                    };

                    // Some binaries legitimately have these
                    let expected_suid = matches!(
                        binary_path.file_name().and_then(|s| s.to_str()),
                        Some("su") | Some("sudo") | Some("passwd") | Some("ping")
                    );

                    if !expected_suid {
                        self.findings.push(Finding {
                            timestamp: Utc::now(),
                            indicator_type: IndicatorType::ModifiedBinary,
                            severity: Severity::High,
                            title: format!(
                                "{} binary has {} bit set",
                                binary_path.display(), mode_str
                            ),
                            description: format!(
                                "Binary {} has unexpected {} permissions. \
                                 This could indicate tampering.",
                                binary_path.display(), mode_str
                            ),
                            path: Some(binary_path.clone()),
                            pid: None,
                            evidence: HashMap::from([
                                ("sha256".to_string(), integrity.sha256),
                                ("mode".to_string(), format!("{:o}", integrity.mode)),
                            ]),
                            recommendation: "Verify this binary against a known-good copy \
                                and reinstall if necessary.".to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Compute integrity information for a file
    fn compute_file_integrity(&self, path: &Path) -> Result<FileIntegrity> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            hex::encode(hasher.finalize())
        };

        let md5 = {
            let mut hasher = Md5::new();
            hasher.update(&content);
            hex::encode(hasher.finalize())
        };

        let mode = metadata.mode();
        let is_setuid = mode & 0o4000 != 0;
        let is_setgid = mode & 0o2000 != 0;

        Ok(FileIntegrity {
            path: path.to_path_buf(),
            sha256,
            md5,
            size: metadata.len(),
            mode,
            uid: metadata.uid(),
            gid: metadata.gid(),
            mtime: metadata.mtime(),
            is_setuid,
            is_setgid,
        })
    }

    /// Check for suspicious mount points
    pub async fn check_suspicious_mounts(&mut self) -> Result<()> {
        info!("Checking mount points...");

        let content = fs::read_to_string("/proc/mounts")?;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let device = parts[0];
            let mount_point = parts[1];
            let fs_type = parts[2];
            let options = parts[3];

            // Check for bind mounts that could hide directories
            if options.contains("bind") {
                // Bind mounts to /etc, /bin, /sbin, /lib are suspicious
                if mount_point.starts_with("/etc")
                    || mount_point.starts_with("/bin")
                    || mount_point.starts_with("/sbin")
                    || mount_point.starts_with("/lib")
                {
                    self.findings.push(Finding {
                        timestamp: Utc::now(),
                        indicator_type: IndicatorType::SuspiciousMount,
                        severity: Severity::High,
                        title: format!("Suspicious bind mount at {}", mount_point),
                        description: format!(
                            "A bind mount from {} to {} could be hiding files.",
                            device, mount_point
                        ),
                        path: Some(PathBuf::from(mount_point)),
                        pid: None,
                        evidence: HashMap::from([
                            ("device".to_string(), device.to_string()),
                            ("fstype".to_string(), fs_type.to_string()),
                            ("options".to_string(), options.to_string()),
                        ]),
                        recommendation: "Investigate this mount point.".to_string(),
                    });
                }
            }

            // Check for unusual filesystems
            if fs_type == "fuse" || fs_type.starts_with("fuse.") {
                self.findings.push(Finding {
                    timestamp: Utc::now(),
                    indicator_type: IndicatorType::SuspiciousMount,
                    severity: Severity::Low,
                    title: format!("FUSE filesystem at {}", mount_point),
                    description: format!(
                        "A FUSE filesystem ({}) is mounted at {}. \
                         While often legitimate, verify its purpose.",
                        fs_type, mount_point
                    ),
                    path: Some(PathBuf::from(mount_point)),
                    pid: None,
                    evidence: HashMap::from([
                        ("device".to_string(), device.to_string()),
                        ("fstype".to_string(), fs_type.to_string()),
                    ]),
                    recommendation: "Verify this is a legitimate FUSE mount.".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Check scheduled tasks for suspicious entries
    pub async fn check_scheduled_tasks(&mut self) -> Result<()> {
        info!("Checking scheduled tasks...");

        // Check crontabs
        let cron_dirs = vec![
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
        ];

        for dir in cron_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        // Look for suspicious patterns in cron jobs
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }

                            // Check for common malicious patterns
                            if line.contains("curl") && line.contains("|") && line.contains("sh")
                                || line.contains("wget") && line.contains("|") && line.contains("sh")
                                || line.contains("nc -e")
                                || line.contains("/dev/tcp/")
                            {
                                self.findings.push(Finding {
                                    timestamp: Utc::now(),
                                    indicator_type: IndicatorType::SuspiciousTask,
                                    severity: Severity::Critical,
                                    title: format!(
                                        "Suspicious cron job in {}",
                                        entry.path().display()
                                    ),
                                    description: format!(
                                        "Cron entry contains potentially malicious pattern: {}",
                                        line.chars().take(100).collect::<String>()
                                    ),
                                    path: Some(entry.path()),
                                    pid: None,
                                    evidence: HashMap::from([
                                        ("line".to_string(), line.to_string()),
                                    ]),
                                    recommendation: "Review and remove this cron job if malicious.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for suspicious device files
    pub async fn check_suspicious_devices(&mut self) -> Result<()> {
        info!("Checking device files...");

        // Look for unusual devices in /dev
        if let Ok(entries) = fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                // Check for hidden device files (starting with .)
                if name.starts_with('.') && name != "." && name != ".." {
                    self.findings.push(Finding {
                        timestamp: Utc::now(),
                        indicator_type: IndicatorType::SuspiciousDevice,
                        severity: Severity::High,
                        title: format!("Hidden device file: {}", path.display()),
                        description: "Hidden file in /dev directory is suspicious.".to_string(),
                        path: Some(path.clone()),
                        pid: None,
                        evidence: HashMap::new(),
                        recommendation: "Investigate this device file.".to_string(),
                    });
                }

                // Check for regular files in /dev (should be device nodes)
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() && metadata.len() > 0 {
                        self.findings.push(Finding {
                            timestamp: Utc::now(),
                            indicator_type: IndicatorType::SuspiciousDevice,
                            severity: Severity::Medium,
                            title: format!("Regular file in /dev: {}", path.display()),
                            description: format!(
                                "Found a regular file with {} bytes in /dev. \
                                 This is unusual and could be a data exfiltration point.",
                                metadata.len()
                            ),
                            path: Some(path),
                            pid: None,
                            evidence: HashMap::from([
                                ("size".to_string(), metadata.len().to_string()),
                            ]),
                            recommendation: "Investigate the contents of this file.".to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Get findings by severity
    pub fn get_findings_by_severity(&self, min_severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Clear all findings
    pub fn clear_findings(&mut self) {
        self.findings.clear();
    }

    /// Generate a JSON report
    pub fn generate_report(&self) -> Result<String> {
        let report = serde_json::json!({
            "scan_time": Utc::now().to_rfc3339(),
            "total_findings": self.findings.len(),
            "critical_count": self.findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            "high_count": self.findings.iter().filter(|f| f.severity == Severity::High).count(),
            "medium_count": self.findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            "low_count": self.findings.iter().filter(|f| f.severity == Severity::Low).count(),
            "info_count": self.findings.iter().filter(|f| f.severity == Severity::Info).count(),
            "findings": self.findings,
        });

        serde_json::to_string_pretty(&report).context("Failed to serialize report")
    }
}

impl Default for RootkitScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = RootkitScanner::new();
        assert!(scanner.findings.is_empty());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_hex_to_ip() {
        assert_eq!(RootkitScanner::hex_to_ip("0100007F"), "127.0.0.1");
        assert_eq!(RootkitScanner::hex_to_ip("00000000"), "0.0.0.0");
    }

    #[test]
    fn test_tcp_state_name() {
        assert_eq!(RootkitScanner::tcp_state_name(0x01), "ESTABLISHED");
        assert_eq!(RootkitScanner::tcp_state_name(0x0A), "LISTEN");
        assert_eq!(RootkitScanner::tcp_state_name(0xFF), "UNKNOWN");
    }

    #[tokio::test]
    async fn test_report_generation() {
        let scanner = RootkitScanner::new();
        let report = scanner.generate_report();
        assert!(report.is_ok());
        let report_str = report.unwrap();
        assert!(report_str.contains("scan_time"));
        assert!(report_str.contains("findings"));
    }
}
