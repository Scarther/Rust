//! # Keylogger Detector Library
//!
//! This module provides advanced keylogger detection capabilities by monitoring
//! Linux input devices, analyzing process behavior, and detecting suspicious patterns.
//!
//! ## Advanced Rust Concepts Demonstrated:
//! - Unsafe Rust for raw pointer manipulation
//! - FFI (Foreign Function Interface) for system calls
//! - Low-level file descriptor operations
//! - Asynchronous programming with tokio
//! - Memory-mapped I/O concepts
//!
//! ## Security Considerations:
//! This tool is for DEFENSIVE purposes only - detecting malicious keyloggers.
//! It requires root privileges to access input devices.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::*;
use evdev::{Device, InputEventKind};
use log::{debug, error, info, warn};
use nix::sys::stat;
use nix::unistd::{Gid, Uid};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysinfo::{ProcessExt, System, SystemExt};
use thiserror::Error;
use tokio::sync::RwLock;

/// Custom error types for keylogger detection operations
///
/// Using thiserror for ergonomic error handling - this is a common pattern
/// in production Rust code for creating domain-specific error types.
#[derive(Error, Debug)]
pub enum DetectorError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Process analysis failed: {0}")]
    ProcessAnalysisError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("System error: {0}")]
    SystemError(String),
}

/// Represents a detected suspicious activity
///
/// This struct uses Serde for serialization, allowing us to output
/// detection results in JSON format for integration with other tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousActivity {
    /// Timestamp of detection
    pub timestamp: DateTime<Utc>,
    /// Type of suspicious activity
    pub activity_type: ActivityType,
    /// Process ID if applicable
    pub pid: Option<u32>,
    /// Process name if applicable
    pub process_name: Option<String>,
    /// File path if applicable
    pub file_path: Option<PathBuf>,
    /// Detailed description
    pub description: String,
    /// Severity level (1-10)
    pub severity: u8,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of suspicious activities we can detect
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ActivityType {
    /// Process reading from input device
    InputDeviceAccess,
    /// Suspicious file descriptor to input device
    SuspiciousFdAccess,
    /// Hidden process detected
    HiddenProcess,
    /// Process hooking keyboard interrupts
    KeyboardHook,
    /// Suspicious shared library loaded
    SuspiciousLibrary,
    /// Process with unusual capabilities
    UnusualCapabilities,
    /// New input device appeared
    NewInputDevice,
    /// Process monitoring /dev/input
    InputMonitoring,
}

/// Information about an input device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDeviceInfo {
    pub path: PathBuf,
    pub name: String,
    pub physical_path: Option<String>,
    pub unique_id: Option<String>,
    pub is_keyboard: bool,
    pub is_mouse: bool,
    pub driver: Option<String>,
    /// File permissions and ownership
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Process information relevant to keylogger detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub open_fds: Vec<FileDescriptor>,
    pub uid: u32,
    pub gid: u32,
    pub parent_pid: Option<u32>,
    pub start_time: Option<u64>,
    pub memory_maps: Vec<MemoryMapping>,
}

/// File descriptor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDescriptor {
    pub fd: i32,
    pub path: PathBuf,
    pub flags: String,
    pub is_input_device: bool,
}

/// Memory mapping information from /proc/[pid]/maps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMapping {
    pub start_addr: u64,
    pub end_addr: u64,
    pub permissions: String,
    pub path: Option<PathBuf>,
}

/// Main detector state
///
/// Uses Arc<RwLock<>> for thread-safe shared state in async context.
/// This is a common pattern for concurrent data access in Rust.
pub struct KeyloggerDetector {
    /// Known input devices
    pub input_devices: Arc<RwLock<HashMap<PathBuf, InputDeviceInfo>>>,
    /// Detected suspicious activities
    pub activities: Arc<RwLock<Vec<SuspiciousActivity>>>,
    /// Known safe processes (whitelist)
    pub whitelist: HashSet<String>,
    /// Suspicious library patterns
    pub suspicious_patterns: Vec<Regex>,
    /// System information handle
    system: Arc<RwLock<System>>,
}

impl KeyloggerDetector {
    /// Create a new keylogger detector instance
    ///
    /// # Example
    /// ```no_run
    /// use keylogger_detector::KeyloggerDetector;
    /// let detector = KeyloggerDetector::new();
    /// ```
    pub fn new() -> Self {
        let mut whitelist = HashSet::new();
        // Common legitimate processes that access input devices
        whitelist.insert("Xorg".to_string());
        whitelist.insert("X".to_string());
        whitelist.insert("gnome-shell".to_string());
        whitelist.insert("kwin_wayland".to_string());
        whitelist.insert("sway".to_string());
        whitelist.insert("weston".to_string());
        whitelist.insert("libinput".to_string());
        whitelist.insert("systemd-logind".to_string());
        whitelist.insert("gdm".to_string());
        whitelist.insert("sddm".to_string());
        whitelist.insert("lightdm".to_string());

        // Patterns for suspicious shared libraries
        let suspicious_patterns = vec![
            Regex::new(r"libkeylog").unwrap(),
            Regex::new(r"libhook").unwrap(),
            Regex::new(r"libinject").unwrap(),
            Regex::new(r"pam_keylog").unwrap(),
            Regex::new(r"ld_preload.*input").unwrap(),
        ];

        Self {
            input_devices: Arc::new(RwLock::new(HashMap::new())),
            activities: Arc::new(RwLock::new(Vec::new())),
            whitelist,
            suspicious_patterns,
            system: Arc::new(RwLock::new(System::new_all())),
        }
    }

    /// Enumerate all input devices on the system
    ///
    /// This function demonstrates several advanced Rust concepts:
    /// 1. Reading from /dev/input/event* devices
    /// 2. Using evdev crate for device capability detection
    /// 3. Error handling with context propagation
    ///
    /// # Safety Considerations
    /// Accessing /dev/input requires appropriate permissions (usually root or input group)
    pub async fn enumerate_input_devices(&self) -> Result<Vec<InputDeviceInfo>> {
        let input_path = Path::new("/dev/input");
        let mut devices = Vec::new();

        if !input_path.exists() {
            return Err(DetectorError::DeviceNotFound(
                "/dev/input directory not found".to_string(),
            )
            .into());
        }

        // Read all event devices
        let entries = fs::read_dir(input_path)
            .context("Failed to read /dev/input directory")?;

        for entry in entries.flatten() {
            let path = entry.path();
            let filename = path.file_name().unwrap_or_default().to_string_lossy();

            // We're interested in event devices
            if !filename.starts_with("event") {
                continue;
            }

            // Try to open the device and get its information
            match self.get_device_info(&path).await {
                Ok(info) => {
                    debug!("Found input device: {} at {:?}", info.name, path);
                    devices.push(info);
                }
                Err(e) => {
                    // Log but don't fail - some devices may be inaccessible
                    warn!("Could not access device {:?}: {}", path, e);
                }
            }
        }

        // Update our internal state
        let mut dev_map = self.input_devices.write().await;
        for device in &devices {
            dev_map.insert(device.path.clone(), device.clone());
        }

        Ok(devices)
    }

    /// Get detailed information about a specific input device
    ///
    /// Uses the evdev crate to query device capabilities.
    /// This is a safe wrapper around what would otherwise require
    /// unsafe ioctl calls.
    async fn get_device_info(&self, path: &Path) -> Result<InputDeviceInfo> {
        // Open the device using evdev
        // This internally uses ioctl calls to query the kernel
        let device = Device::open(path)
            .context(format!("Failed to open device {:?}", path))?;

        let name = device.name().unwrap_or("Unknown").to_string();

        // Check device capabilities to determine type
        let is_keyboard = device.supported_keys().map_or(false, |keys| {
            // Check if device has typical keyboard keys
            keys.contains(evdev::Key::KEY_A) &&
            keys.contains(evdev::Key::KEY_ENTER)
        });

        let is_mouse = device.supported_events().contains(evdev::EventType::RELATIVE);

        // Get file metadata for permissions
        let metadata = fs::metadata(path)?;

        Ok(InputDeviceInfo {
            path: path.to_path_buf(),
            name,
            physical_path: device.physical_path().map(|s| s.to_string()),
            unique_id: device.unique_name().map(|s| s.to_string()),
            is_keyboard,
            is_mouse,
            driver: None, // Would require additional parsing
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
        })
    }

    /// Scan all processes for suspicious input device access
    ///
    /// This is the core detection function that:
    /// 1. Enumerates all processes via /proc
    /// 2. Checks their open file descriptors
    /// 3. Analyzes memory mappings for suspicious libraries
    /// 4. Detects hidden processes
    ///
    /// # Advanced Concepts:
    /// - Reading from /proc filesystem
    /// - Parsing memory maps
    /// - File descriptor analysis
    pub async fn scan_processes(&self) -> Result<Vec<SuspiciousActivity>> {
        let mut findings = Vec::new();

        // Refresh system information
        {
            let mut system = self.system.write().await;
            system.refresh_all();
        }

        // Get list of processes
        let system = self.system.read().await;
        let processes: Vec<_> = system.processes().iter().collect();

        for (pid, process) in processes {
            let pid_u32 = pid.as_u32();
            let proc_name = process.name().to_string();

            // Skip whitelisted processes
            if self.whitelist.contains(&proc_name) {
                continue;
            }

            // Check file descriptors
            if let Ok(fds) = self.get_process_fds(pid_u32).await {
                for fd in &fds {
                    if fd.is_input_device {
                        let activity = SuspiciousActivity {
                            timestamp: Utc::now(),
                            activity_type: ActivityType::InputDeviceAccess,
                            pid: Some(pid_u32),
                            process_name: Some(proc_name.clone()),
                            file_path: Some(fd.path.clone()),
                            description: format!(
                                "Process '{}' (PID {}) has open fd to input device: {:?}",
                                proc_name, pid_u32, fd.path
                            ),
                            severity: 7,
                            metadata: HashMap::from([
                                ("fd".to_string(), fd.fd.to_string()),
                                ("flags".to_string(), fd.flags.clone()),
                            ]),
                        };
                        findings.push(activity);
                    }
                }
            }

            // Check memory mappings for suspicious libraries
            if let Ok(maps) = self.get_memory_maps(pid_u32).await {
                for map in &maps {
                    if let Some(path) = &map.path {
                        let path_str = path.to_string_lossy();
                        for pattern in &self.suspicious_patterns {
                            if pattern.is_match(&path_str) {
                                let activity = SuspiciousActivity {
                                    timestamp: Utc::now(),
                                    activity_type: ActivityType::SuspiciousLibrary,
                                    pid: Some(pid_u32),
                                    process_name: Some(proc_name.clone()),
                                    file_path: Some(path.clone()),
                                    description: format!(
                                        "Suspicious library loaded in process '{}': {:?}",
                                        proc_name, path
                                    ),
                                    severity: 9,
                                    metadata: HashMap::from([
                                        ("addr_range".to_string(),
                                         format!("{:#x}-{:#x}", map.start_addr, map.end_addr)),
                                        ("permissions".to_string(), map.permissions.clone()),
                                    ]),
                                };
                                findings.push(activity);
                            }
                        }
                    }
                }
            }
        }

        // Store findings
        let mut activities = self.activities.write().await;
        activities.extend(findings.clone());

        Ok(findings)
    }

    /// Get open file descriptors for a process
    ///
    /// Reads from /proc/[pid]/fd and resolves symlinks.
    /// This is how we determine what files a process has open.
    ///
    /// # Implementation Details:
    /// /proc/[pid]/fd contains symlinks where:
    /// - The symlink name is the file descriptor number
    /// - The symlink target is the path of the open file
    async fn get_process_fds(&self, pid: u32) -> Result<Vec<FileDescriptor>> {
        let fd_path = PathBuf::from(format!("/proc/{}/fd", pid));
        let mut fds = Vec::new();

        if !fd_path.exists() {
            return Ok(fds);
        }

        let entries = match fs::read_dir(&fd_path) {
            Ok(e) => e,
            Err(_) => return Ok(fds), // Process may have exited
        };

        for entry in entries.flatten() {
            let fd_link = entry.path();

            // Read the symlink to get the actual file path
            let target = match fs::read_link(&fd_link) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let fd_num: i32 = entry
                .file_name()
                .to_string_lossy()
                .parse()
                .unwrap_or(-1);

            let target_str = target.to_string_lossy();
            let is_input_device = target_str.contains("/dev/input/");

            // Get fd flags from /proc/[pid]/fdinfo/[fd]
            let flags = self.get_fd_flags(pid, fd_num).await.unwrap_or_default();

            fds.push(FileDescriptor {
                fd: fd_num,
                path: target,
                flags,
                is_input_device,
            });
        }

        Ok(fds)
    }

    /// Get file descriptor flags from fdinfo
    async fn get_fd_flags(&self, pid: u32, fd: i32) -> Result<String> {
        let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd);
        let content = fs::read_to_string(&fdinfo_path)?;

        for line in content.lines() {
            if line.starts_with("flags:") {
                return Ok(line.trim_start_matches("flags:").trim().to_string());
            }
        }

        Ok(String::new())
    }

    /// Parse memory mappings from /proc/[pid]/maps
    ///
    /// The maps file format is:
    /// address           perms offset   dev   inode   pathname
    /// 7f1234000-7f1235000 r-xp 00000000 08:01 12345  /lib/libc.so.6
    ///
    /// # Advanced Concept:
    /// Memory mapping analysis is crucial for:
    /// - Detecting injected code
    /// - Finding suspicious shared libraries
    /// - Analyzing LD_PRELOAD attacks
    async fn get_memory_maps(&self, pid: u32) -> Result<Vec<MemoryMapping>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let file = File::open(&maps_path)?;
        let reader = BufReader::new(file);
        let mut maps = Vec::new();

        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            // Parse address range (e.g., "7f1234000-7f1235000")
            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() != 2 {
                continue;
            }

            let start_addr = u64::from_str_radix(addr_range[0], 16).unwrap_or(0);
            let end_addr = u64::from_str_radix(addr_range[1], 16).unwrap_or(0);
            let permissions = parts[1].to_string();
            let path = if parts.len() > 5 {
                Some(PathBuf::from(parts[5..].join(" ")))
            } else {
                None
            };

            maps.push(MemoryMapping {
                start_addr,
                end_addr,
                permissions,
                path,
            });
        }

        Ok(maps)
    }

    /// Detect hidden processes
    ///
    /// Hidden processes are a common technique used by rootkits.
    /// We detect them by comparing:
    /// 1. PIDs from /proc
    /// 2. PIDs from sysinfo
    /// 3. PIDs from scanning /proc/[pid]/task
    ///
    /// Discrepancies may indicate process hiding.
    pub async fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousActivity>> {
        let mut findings = Vec::new();

        // Method 1: Direct /proc enumeration
        let mut proc_pids: HashSet<u32> = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    proc_pids.insert(pid);
                }
            }
        }

        // Method 2: Using sysinfo
        let mut sysinfo_pids: HashSet<u32> = HashSet::new();
        {
            let system = self.system.read().await;
            for pid in system.processes().keys() {
                sysinfo_pids.insert(pid.as_u32());
            }
        }

        // Method 3: Brute force scan (1-65535)
        // This is computationally expensive but thorough
        let mut brute_pids: HashSet<u32> = HashSet::new();
        for pid in 1..=65535u32 {
            let proc_path = format!("/proc/{}", pid);
            if Path::new(&proc_path).exists() {
                brute_pids.insert(pid);
            }
        }

        // Check for discrepancies
        // Hidden from /proc but found by brute force
        for pid in brute_pids.difference(&proc_pids) {
            let activity = SuspiciousActivity {
                timestamp: Utc::now(),
                activity_type: ActivityType::HiddenProcess,
                pid: Some(*pid),
                process_name: None,
                file_path: None,
                description: format!(
                    "Potentially hidden process: PID {} found by brute force but not in /proc listing",
                    pid
                ),
                severity: 10,
                metadata: HashMap::new(),
            };
            findings.push(activity);
        }

        // In sysinfo but not in /proc (should not happen normally)
        for pid in sysinfo_pids.difference(&proc_pids) {
            if !brute_pids.contains(pid) {
                let activity = SuspiciousActivity {
                    timestamp: Utc::now(),
                    activity_type: ActivityType::HiddenProcess,
                    pid: Some(*pid),
                    process_name: None,
                    file_path: None,
                    description: format!(
                        "Process inconsistency: PID {} in sysinfo but not in /proc",
                        pid
                    ),
                    severity: 8,
                    metadata: HashMap::new(),
                };
                findings.push(activity);
            }
        }

        Ok(findings)
    }

    /// Monitor input devices in real-time for suspicious access
    ///
    /// This function uses inotify (via the notify crate) to watch for:
    /// 1. New input devices being created
    /// 2. Access to existing input devices
    /// 3. Suspicious device creation patterns
    ///
    /// # Advanced Concept:
    /// File system notification is crucial for real-time detection.
    /// We use the notify crate which provides a safe abstraction over
    /// Linux's inotify system.
    pub async fn start_monitoring(&self) -> Result<tokio::sync::mpsc::Receiver<SuspiciousActivity>> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc::channel;

        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let activities = self.activities.clone();

        // Spawn a blocking task for the file watcher
        let tx_clone = tx.clone();
        tokio::task::spawn_blocking(move || {
            let (sync_tx, sync_rx) = channel();

            let mut watcher = RecommendedWatcher::new(sync_tx, Config::default())
                .expect("Failed to create watcher");

            watcher
                .watch(Path::new("/dev/input"), RecursiveMode::Recursive)
                .expect("Failed to watch /dev/input");

            // Also watch /proc for new processes
            // Note: This might generate a lot of events
            if let Err(e) = watcher.watch(Path::new("/proc"), RecursiveMode::NonRecursive) {
                warn!("Could not watch /proc: {}", e);
            }

            loop {
                match sync_rx.recv() {
                    Ok(Ok(event)) => {
                        // Process the event
                        for path in event.paths {
                            if path.to_string_lossy().contains("/dev/input/") {
                                let activity = SuspiciousActivity {
                                    timestamp: Utc::now(),
                                    activity_type: ActivityType::NewInputDevice,
                                    pid: None,
                                    process_name: None,
                                    file_path: Some(path.clone()),
                                    description: format!(
                                        "Input device activity detected: {:?} - {:?}",
                                        event.kind, path
                                    ),
                                    severity: 5,
                                    metadata: HashMap::new(),
                                };

                                if let Err(e) = tx_clone.blocking_send(activity) {
                                    error!("Failed to send activity: {}", e);
                                    return;
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Watch error: {:?}", e);
                    }
                    Err(e) => {
                        error!("Channel error: {:?}", e);
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Check for LD_PRELOAD attacks
    ///
    /// LD_PRELOAD is a common attack vector for keyloggers.
    /// When set, the dynamic linker loads specified libraries before all others,
    /// allowing interception of library calls.
    ///
    /// We check:
    /// 1. Global LD_PRELOAD in /etc/ld.so.preload
    /// 2. Per-process LD_PRELOAD in environment
    pub async fn check_ld_preload(&self) -> Result<Vec<SuspiciousActivity>> {
        let mut findings = Vec::new();

        // Check global LD_PRELOAD
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            let content = fs::read_to_string(preload_path)?;
            if !content.trim().is_empty() {
                let activity = SuspiciousActivity {
                    timestamp: Utc::now(),
                    activity_type: ActivityType::SuspiciousLibrary,
                    pid: None,
                    process_name: None,
                    file_path: Some(preload_path.to_path_buf()),
                    description: format!(
                        "Global LD_PRELOAD detected in /etc/ld.so.preload: {}",
                        content.trim()
                    ),
                    severity: 8,
                    metadata: HashMap::from([
                        ("content".to_string(), content.trim().to_string()),
                    ]),
                };
                findings.push(activity);
            }
        }

        // Check per-process LD_PRELOAD
        let system = self.system.read().await;
        for (pid, process) in system.processes() {
            let environ_path = format!("/proc/{}/environ", pid.as_u32());
            if let Ok(content) = fs::read_to_string(&environ_path) {
                // Environment variables are null-separated
                for env_var in content.split('\0') {
                    if env_var.starts_with("LD_PRELOAD=") {
                        let value = env_var.trim_start_matches("LD_PRELOAD=");
                        let activity = SuspiciousActivity {
                            timestamp: Utc::now(),
                            activity_type: ActivityType::SuspiciousLibrary,
                            pid: Some(pid.as_u32()),
                            process_name: Some(process.name().to_string()),
                            file_path: None,
                            description: format!(
                                "LD_PRELOAD set for process '{}' (PID {}): {}",
                                process.name(), pid.as_u32(), value
                            ),
                            severity: 7,
                            metadata: HashMap::from([
                                ("ld_preload".to_string(), value.to_string()),
                            ]),
                        };
                        findings.push(activity);
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Generate a comprehensive security report
    pub async fn generate_report(&self) -> Result<String> {
        let activities = self.activities.read().await;
        let devices = self.input_devices.read().await;

        let report = serde_json::json!({
            "report_time": Utc::now().to_rfc3339(),
            "total_findings": activities.len(),
            "critical_findings": activities.iter()
                .filter(|a| a.severity >= 8)
                .count(),
            "high_findings": activities.iter()
                .filter(|a| a.severity >= 6 && a.severity < 8)
                .count(),
            "medium_findings": activities.iter()
                .filter(|a| a.severity >= 4 && a.severity < 6)
                .count(),
            "low_findings": activities.iter()
                .filter(|a| a.severity < 4)
                .count(),
            "input_devices": devices.len(),
            "keyboard_devices": devices.values()
                .filter(|d| d.is_keyboard)
                .count(),
            "findings": activities.clone(),
        });

        serde_json::to_string_pretty(&report).context("Failed to serialize report")
    }

    /// Add a process to the whitelist
    pub fn add_to_whitelist(&mut self, process_name: &str) {
        self.whitelist.insert(process_name.to_string());
    }

    /// Clear all recorded activities
    pub async fn clear_activities(&self) {
        let mut activities = self.activities.write().await;
        activities.clear();
    }
}

impl Default for KeyloggerDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Raw pointer operations for advanced device analysis
///
/// # Safety
/// This module contains unsafe code for low-level device operations.
/// It's separated to make safety audits easier.
pub mod raw_ops {
    use std::os::unix::io::RawFd;
    use std::ptr;

    /// ioctl request codes for input devices
    /// These are typically defined in <linux/input.h>
    pub const EVIOCGNAME: u64 = 0x40004506; // Get device name
    pub const EVIOCGID: u64 = 0x40084502;   // Get device ID

    /// Device ID structure matching linux/input.h
    #[repr(C)]
    pub struct InputId {
        pub bustype: u16,
        pub vendor: u16,
        pub product: u16,
        pub version: u16,
    }

    /// Perform raw ioctl call to get device name
    ///
    /// # Safety
    /// This function is unsafe because:
    /// 1. It uses raw file descriptors
    /// 2. It performs ioctl system calls
    /// 3. It writes to a raw pointer
    ///
    /// The caller must ensure:
    /// - fd is a valid, open file descriptor
    /// - buf points to valid memory of at least len bytes
    #[cfg(target_os = "linux")]
    pub unsafe fn get_device_name_raw(fd: RawFd, buf: *mut u8, len: usize) -> i32 {
        // Using libc for ioctl
        // The EVIOCGNAME ioctl takes the buffer size encoded in the request
        let request = 0x40004506 | ((len as u64) << 16);
        libc::ioctl(fd, request as libc::c_ulong, buf)
    }

    /// Get device ID via raw ioctl
    ///
    /// # Safety
    /// Same safety requirements as get_device_name_raw
    #[cfg(target_os = "linux")]
    pub unsafe fn get_device_id_raw(fd: RawFd) -> Option<InputId> {
        let mut id: InputId = InputId {
            bustype: 0,
            vendor: 0,
            product: 0,
            version: 0,
        };

        let result = libc::ioctl(
            fd,
            EVIOCGID as libc::c_ulong,
            &mut id as *mut InputId,
        );

        if result == 0 {
            Some(id)
        } else {
            None
        }
    }

    /// Read raw input events from device
    ///
    /// # Safety
    /// - fd must be a valid input device file descriptor
    /// - The caller must have appropriate permissions
    #[cfg(target_os = "linux")]
    pub unsafe fn read_raw_events(fd: RawFd, events: *mut libc::input_event, max_events: usize) -> isize {
        let bytes_to_read = max_events * std::mem::size_of::<libc::input_event>();
        libc::read(fd, events as *mut libc::c_void, bytes_to_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detector_creation() {
        let detector = KeyloggerDetector::new();
        assert!(!detector.whitelist.is_empty());
        assert!(!detector.suspicious_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_whitelist_operations() {
        let mut detector = KeyloggerDetector::new();
        detector.add_to_whitelist("test_process");
        assert!(detector.whitelist.contains("test_process"));
    }

    #[tokio::test]
    async fn test_activity_clearing() {
        let detector = KeyloggerDetector::new();

        // Add a test activity
        {
            let mut activities = detector.activities.write().await;
            activities.push(SuspiciousActivity {
                timestamp: Utc::now(),
                activity_type: ActivityType::InputDeviceAccess,
                pid: Some(1234),
                process_name: Some("test".to_string()),
                file_path: None,
                description: "Test activity".to_string(),
                severity: 5,
                metadata: HashMap::new(),
            });
        }

        // Verify it was added
        {
            let activities = detector.activities.read().await;
            assert_eq!(activities.len(), 1);
        }

        // Clear and verify
        detector.clear_activities().await;
        {
            let activities = detector.activities.read().await;
            assert!(activities.is_empty());
        }
    }

    #[test]
    fn test_memory_mapping_parsing() {
        // Test the regex patterns used for memory map parsing
        let test_line = "7f1234000000-7f1235000000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6";
        let parts: Vec<&str> = test_line.split_whitespace().collect();

        assert_eq!(parts[0], "7f1234000000-7f1235000000");
        assert_eq!(parts[1], "r-xp");
        assert!(parts.len() >= 6);
    }

    #[test]
    fn test_suspicious_patterns() {
        let detector = KeyloggerDetector::new();

        // Test that patterns match suspicious libraries
        let suspicious_libs = vec![
            "/lib/libkeylog.so",
            "/usr/lib/libhook_input.so",
            "/tmp/libinject.so",
        ];

        for lib in suspicious_libs {
            let matches = detector.suspicious_patterns
                .iter()
                .any(|p| p.is_match(lib));
            assert!(matches, "Pattern should match: {}", lib);
        }

        // Test that normal libraries don't match
        let normal_libs = vec![
            "/lib/libc.so.6",
            "/lib/libpthread.so.0",
        ];

        for lib in normal_libs {
            let matches = detector.suspicious_patterns
                .iter()
                .any(|p| p.is_match(lib));
            assert!(!matches, "Pattern should not match: {}", lib);
        }
    }

    #[tokio::test]
    async fn test_report_generation() {
        let detector = KeyloggerDetector::new();
        let report = detector.generate_report().await;
        assert!(report.is_ok());

        let report_str = report.unwrap();
        assert!(report_str.contains("report_time"));
        assert!(report_str.contains("total_findings"));
    }

    #[test]
    fn test_input_id_struct_size() {
        // Verify our struct matches the kernel's definition
        use super::raw_ops::InputId;
        assert_eq!(std::mem::size_of::<InputId>(), 8);
    }
}
