//! AU03 Disk Monitor - Disk Space Monitoring Tool
//!
//! This tool provides comprehensive disk space monitoring and alerting.
//! Essential for maintaining system health and detecting potential issues.
//!
//! Features:
//! - Monitor disk usage across all filesystems
//! - Set warning and critical thresholds
//! - Real-time monitoring mode
//! - Generate alerts when thresholds exceeded
//! - Track disk usage trends over time
//! - Find large files and directories
//! - Monitor specific directories
//! - Export metrics to JSON
//!
//! Security applications:
//! - Detect disk-filling attacks
//! - Monitor log growth for anomalies
//! - Ensure adequate space for security tools
//! - Track unauthorized large file creation

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use sysinfo::{DiskExt, System, SystemExt};
use tabled::{Table, Tabled};

/// Disk Monitor - Comprehensive disk space monitoring tool
#[derive(Parser)]
#[command(name = "disk-monitor")]
#[command(author = "Security Engineer")]
#[command(version = "1.0")]
#[command(about = "Monitor disk space and generate alerts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show disk usage summary
    Status {
        /// Show all filesystems including virtual
        #[arg(short, long)]
        all: bool,
    },

    /// Monitor disk space in real-time
    Monitor {
        /// Warning threshold percentage
        #[arg(short, long, default_value = "80")]
        warning: u8,

        /// Critical threshold percentage
        #[arg(short, long, default_value = "90")]
        critical: u8,

        /// Check interval in seconds
        #[arg(short, long, default_value = "60")]
        interval: u64,

        /// Specific paths to monitor (comma-separated)
        #[arg(short, long)]
        paths: Option<String>,

        /// Send alerts (email, file, or both)
        #[arg(short, long)]
        alert_method: Option<String>,

        /// Alert file path
        #[arg(long)]
        alert_file: Option<PathBuf>,
    },

    /// Find large files
    FindLarge {
        /// Starting directory
        #[arg(short, long, default_value = "/")]
        path: PathBuf,

        /// Minimum file size (e.g., 100M, 1G)
        #[arg(short, long, default_value = "100M")]
        size: String,

        /// Maximum results to show
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Include hidden files
        #[arg(long)]
        hidden: bool,
    },

    /// Show directory sizes
    DirSize {
        /// Directory to analyze
        path: PathBuf,

        /// Depth of subdirectory analysis
        #[arg(short, long, default_value = "1")]
        depth: usize,

        /// Sort by size
        #[arg(short, long)]
        sort: bool,
    },

    /// Track disk usage trends
    Trends {
        /// Data file for historical tracking
        #[arg(short, long, default_value = "disk_trends.json")]
        data_file: PathBuf,

        /// Number of days to show
        #[arg(short, long, default_value = "7")]
        days: usize,

        /// Record current usage
        #[arg(short, long)]
        record: bool,
    },

    /// Check inode usage
    Inodes {
        /// Specific path to check
        path: Option<PathBuf>,
    },

    /// Analyze filesystem health
    Health {
        /// Check specific filesystem
        filesystem: Option<String>,
    },

    /// Set up alert configuration
    ConfigAlert {
        /// Email address for alerts
        #[arg(short, long)]
        email: Option<String>,

        /// Webhook URL for alerts
        #[arg(short, long)]
        webhook: Option<String>,

        /// Save configuration
        #[arg(short, long)]
        save: bool,

        /// Configuration file
        #[arg(short, long, default_value = "disk_monitor.conf")]
        config: PathBuf,
    },

    /// Export disk metrics
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Include historical data
        #[arg(short, long)]
        history: bool,
    },

    /// Clean up old/temporary files
    Cleanup {
        /// Target directory
        path: PathBuf,

        /// Delete files older than N days
        #[arg(short, long, default_value = "30")]
        older_than: u64,

        /// File patterns to match (e.g., "*.log,*.tmp")
        #[arg(short, long)]
        patterns: Option<String>,

        /// Dry run (don't actually delete)
        #[arg(short, long)]
        dry_run: bool,
    },
}

/// Disk usage information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct DiskInfo {
    #[tabled(rename = "Filesystem")]
    filesystem: String,
    #[tabled(rename = "Mount Point")]
    mount_point: String,
    #[tabled(rename = "Total")]
    total: String,
    #[tabled(rename = "Used")]
    used: String,
    #[tabled(rename = "Available")]
    available: String,
    #[tabled(rename = "Use%")]
    use_percent: String,
    #[tabled(rename = "Status")]
    status: String,
}

/// Large file information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct LargeFile {
    #[tabled(rename = "Path")]
    #[tabled(display_with = "truncate_path")]
    path: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Modified")]
    modified: String,
    #[tabled(rename = "Owner")]
    owner: String,
}

fn truncate_path(path: &String) -> String {
    if path.len() > 60 {
        format!("...{}", &path[path.len() - 57..])
    } else {
        path.clone()
    }
}

/// Directory size information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct DirSizeInfo {
    #[tabled(rename = "Directory")]
    path: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Files")]
    file_count: u64,
    #[tabled(rename = "Dirs")]
    dir_count: u64,
}

/// Trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrendPoint {
    timestamp: String,
    filesystem: String,
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    use_percent: f64,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertConfig {
    email: Option<String>,
    webhook: Option<String>,
    warning_threshold: u8,
    critical_threshold: u8,
}

/// Inode usage information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct InodeInfo {
    #[tabled(rename = "Filesystem")]
    filesystem: String,
    #[tabled(rename = "Total Inodes")]
    total: String,
    #[tabled(rename = "Used")]
    used: String,
    #[tabled(rename = "Available")]
    available: String,
    #[tabled(rename = "Use%")]
    use_percent: String,
}

/// Disk health information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskHealth {
    filesystem: String,
    mount_point: String,
    fs_type: String,
    mount_options: Vec<String>,
    is_readonly: bool,
    errors: Vec<String>,
    smart_status: Option<String>,
}

/// Disk monitor implementation
struct DiskMonitor {
    system: System,
    verbose: bool,
}

impl DiskMonitor {
    fn new(verbose: bool) -> Self {
        let mut system = System::new_all();
        system.refresh_disks_list();
        Self { system, verbose }
    }

    /// Get disk usage status
    fn get_disk_status(&mut self, show_all: bool) -> Result<Vec<DiskInfo>> {
        self.system.refresh_disks();
        let mut disks = Vec::new();

        for disk in self.system.disks() {
            let mount_point = disk.mount_point().to_string_lossy().to_string();

            // Skip virtual filesystems unless show_all is true
            if !show_all {
                if mount_point.starts_with("/sys")
                    || mount_point.starts_with("/proc")
                    || mount_point.starts_with("/dev")
                    || mount_point.starts_with("/run")
                    || mount_point.starts_with("/snap")
                {
                    continue;
                }
            }

            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            let use_percent = if total > 0 {
                (used as f64 / total as f64 * 100.0) as u8
            } else {
                0
            };

            let status = if use_percent >= 90 {
                "CRITICAL".red().to_string()
            } else if use_percent >= 80 {
                "WARNING".yellow().to_string()
            } else {
                "OK".green().to_string()
            };

            disks.push(DiskInfo {
                filesystem: disk.name().to_string_lossy().to_string(),
                mount_point,
                total: format_size(total),
                used: format_size(used),
                available: format_size(available),
                use_percent: format!("{}%", use_percent),
                status,
            });
        }

        Ok(disks)
    }

    /// Monitor disks in real-time
    fn monitor(
        &mut self,
        warning: u8,
        critical: u8,
        interval: u64,
        paths: Option<&str>,
        alert_method: Option<&str>,
        alert_file: Option<&PathBuf>,
    ) -> Result<()> {
        println!("{} Starting disk monitor...", "[*]".blue());
        println!(
            "  Warning threshold: {}%, Critical threshold: {}%",
            warning, critical
        );
        println!("  Check interval: {} seconds", interval);
        println!("{}", "=".repeat(70));

        let paths_to_monitor: Option<Vec<String>> = paths.map(|p| {
            p.split(',').map(|s| s.trim().to_string()).collect()
        });

        let mut previous_alerts: HashMap<String, u8> = HashMap::new();

        loop {
            self.system.refresh_disks();
            let now: DateTime<Local> = Local::now();

            print!("\x1B[2J\x1B[1;1H"); // Clear screen

            println!(
                "{} Disk Monitor - {}",
                "[*]".blue(),
                now.format("%Y-%m-%d %H:%M:%S")
            );
            println!("{}", "=".repeat(70));

            let mut alerts = Vec::new();

            for disk in self.system.disks() {
                let mount_point = disk.mount_point().to_string_lossy().to_string();

                // Check if we should monitor this path
                if let Some(ref paths) = paths_to_monitor {
                    if !paths.iter().any(|p| mount_point.starts_with(p)) {
                        continue;
                    }
                }

                // Skip virtual filesystems
                if mount_point.starts_with("/sys")
                    || mount_point.starts_with("/proc")
                    || mount_point.starts_with("/dev/shm")
                {
                    continue;
                }

                let total = disk.total_space();
                let available = disk.available_space();
                let used = total.saturating_sub(available);
                let use_percent = if total > 0 {
                    (used as f64 / total as f64 * 100.0) as u8
                } else {
                    0
                };

                // Create visual bar
                let bar = create_usage_bar(use_percent);

                let status_color = if use_percent >= critical {
                    "CRITICAL".red().bold()
                } else if use_percent >= warning {
                    "WARNING".yellow()
                } else {
                    "OK".green()
                };

                println!(
                    "  {} {} [{}] {}% - {} / {}",
                    status_color,
                    mount_point,
                    bar,
                    use_percent,
                    format_size(used),
                    format_size(total)
                );

                // Check for alerts
                if use_percent >= critical {
                    let prev = previous_alerts.get(&mount_point).copied().unwrap_or(0);
                    if prev < critical {
                        alerts.push(format!(
                            "CRITICAL: {} at {}% usage ({} / {})",
                            mount_point,
                            use_percent,
                            format_size(used),
                            format_size(total)
                        ));
                    }
                    previous_alerts.insert(mount_point.clone(), use_percent);
                } else if use_percent >= warning {
                    let prev = previous_alerts.get(&mount_point).copied().unwrap_or(0);
                    if prev < warning {
                        alerts.push(format!(
                            "WARNING: {} at {}% usage ({} / {})",
                            mount_point,
                            use_percent,
                            format_size(used),
                            format_size(total)
                        ));
                    }
                    previous_alerts.insert(mount_point.clone(), use_percent);
                }
            }

            // Handle alerts
            if !alerts.is_empty() {
                println!("\n{} Active Alerts:", "[!]".red().bold());
                for alert in &alerts {
                    println!("  - {}", alert.red());

                    // Write to alert file if specified
                    if let Some(file_path) = alert_file {
                        let mut file = fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(file_path)?;
                        writeln!(file, "{} - {}", now.format("%Y-%m-%d %H:%M:%S"), alert)?;
                    }
                }
            }

            println!("\n{}", "=".repeat(70));
            println!("Press Ctrl+C to stop monitoring");

            std::thread::sleep(Duration::from_secs(interval));
        }
    }

    /// Find large files
    fn find_large_files(
        &self,
        path: &PathBuf,
        min_size: &str,
        limit: usize,
        include_hidden: bool,
    ) -> Result<Vec<LargeFile>> {
        println!("{} Searching for large files in {}...", "[*]".blue(), path.display());

        let min_bytes = parse_size(min_size)?;
        let mut files = Vec::new();

        // Use find command for efficiency
        let mut cmd = Command::new("find");
        cmd.arg(path)
            .args(["-type", "f"])
            .args(["-size", &format!("+{}c", min_bytes)]);

        if !include_hidden {
            cmd.args(["-not", "-path", "*/\\.*"]);
        }

        let output = cmd.output().context("Failed to run find command")?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let file_path = PathBuf::from(line.trim());
            if let Ok(metadata) = fs::metadata(&file_path) {
                let size = metadata.len();
                let modified = metadata.modified().ok().map(|t| {
                    let datetime: DateTime<Local> = t.into();
                    datetime.format("%Y-%m-%d %H:%M").to_string()
                }).unwrap_or_else(|| "-".to_string());

                // Get owner
                let owner = self.get_file_owner(&file_path).unwrap_or_else(|| "-".to_string());

                files.push(LargeFile {
                    path: file_path.to_string_lossy().to_string(),
                    size: format_size(size),
                    modified,
                    owner,
                });
            }
        }

        // Sort by size descending
        files.sort_by(|a, b| {
            let size_a = parse_size(&a.size).unwrap_or(0);
            let size_b = parse_size(&b.size).unwrap_or(0);
            size_b.cmp(&size_a)
        });

        // Limit results
        files.truncate(limit);

        Ok(files)
    }

    /// Get file owner
    fn get_file_owner(&self, path: &PathBuf) -> Option<String> {
        let output = Command::new("stat")
            .args(["-c", "%U", &path.to_string_lossy()])
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get directory sizes
    fn get_dir_sizes(&self, path: &PathBuf, depth: usize, sort: bool) -> Result<Vec<DirSizeInfo>> {
        println!("{} Analyzing directory sizes in {}...", "[*]".blue(), path.display());

        let mut dirs = Vec::new();

        let output = Command::new("du")
            .args(["-d", &depth.to_string(), "-b", &path.to_string_lossy()])
            .output()
            .context("Failed to run du command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let size: u64 = parts[0].parse().unwrap_or(0);
                let dir_path = parts[1..].join(" ");

                // Count files and directories
                let (file_count, dir_count) = self.count_entries(&PathBuf::from(&dir_path));

                dirs.push(DirSizeInfo {
                    path: dir_path,
                    size: format_size(size),
                    file_count,
                    dir_count,
                });
            }
        }

        if sort {
            dirs.sort_by(|a, b| {
                let size_a = parse_size(&a.size).unwrap_or(0);
                let size_b = parse_size(&b.size).unwrap_or(0);
                size_b.cmp(&size_a)
            });
        }

        Ok(dirs)
    }

    /// Count files and directories in a path
    fn count_entries(&self, path: &PathBuf) -> (u64, u64) {
        let mut files = 0u64;
        let mut dirs = 0u64;

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        files += 1;
                    } else if ft.is_dir() {
                        dirs += 1;
                    }
                }
            }
        }

        (files, dirs)
    }

    /// Record disk usage trends
    fn record_trends(&mut self, data_file: &PathBuf) -> Result<()> {
        println!("{} Recording disk usage trends...", "[*]".blue());

        self.system.refresh_disks();
        let now: DateTime<Local> = Local::now();
        let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

        // Read existing data
        let mut trends: Vec<TrendPoint> = if data_file.exists() {
            let content = fs::read_to_string(data_file)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Add new data points
        for disk in self.system.disks() {
            let mount_point = disk.mount_point().to_string_lossy().to_string();

            // Skip virtual filesystems
            if mount_point.starts_with("/sys")
                || mount_point.starts_with("/proc")
                || mount_point.starts_with("/dev")
                || mount_point.starts_with("/run")
            {
                continue;
            }

            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            let use_percent = if total > 0 {
                used as f64 / total as f64 * 100.0
            } else {
                0.0
            };

            trends.push(TrendPoint {
                timestamp: timestamp.clone(),
                filesystem: mount_point,
                total_bytes: total,
                used_bytes: used,
                available_bytes: available,
                use_percent,
            });
        }

        // Save trends
        let json = serde_json::to_string_pretty(&trends)?;
        fs::write(data_file, json)?;

        println!("{} Trends recorded to {}", "[+]".green(), data_file.display());
        Ok(())
    }

    /// Show disk usage trends
    fn show_trends(&self, data_file: &PathBuf, days: usize) -> Result<()> {
        if !data_file.exists() {
            anyhow::bail!("No trend data found. Use --record to start tracking.");
        }

        let content = fs::read_to_string(data_file)?;
        let trends: Vec<TrendPoint> = serde_json::from_str(&content)?;

        // Group by filesystem
        let mut by_fs: HashMap<String, Vec<&TrendPoint>> = HashMap::new();
        for point in &trends {
            by_fs.entry(point.filesystem.clone())
                .or_insert_with(Vec::new)
                .push(point);
        }

        println!("{} Disk Usage Trends:", "[*]".blue());
        println!("{}", "=".repeat(70));

        for (filesystem, points) in &by_fs {
            println!("\n{} {}", "[*]".cyan(), filesystem);

            // Show recent data points
            let recent: Vec<_> = points.iter().rev().take(days * 24).collect();

            if recent.len() >= 2 {
                let newest = recent[0];
                let oldest = recent[recent.len() - 1];

                let change = newest.use_percent - oldest.use_percent;
                let change_str = if change > 0.0 {
                    format!("+{:.1}%", change).red().to_string()
                } else if change < 0.0 {
                    format!("{:.1}%", change).green().to_string()
                } else {
                    "0%".to_string()
                };

                println!(
                    "  Current: {:.1}% | Change over period: {}",
                    newest.use_percent, change_str
                );
                println!(
                    "  Used: {} / {}",
                    format_size(newest.used_bytes),
                    format_size(newest.total_bytes)
                );

                // Calculate daily rate of change
                if !recent.is_empty() {
                    let daily_change = change / (recent.len() as f64 / 24.0);
                    if daily_change.abs() > 0.1 {
                        println!(
                            "  Daily change rate: {:.2}%",
                            daily_change
                        );

                        // Project when disk will be full
                        if daily_change > 0.0 {
                            let days_until_full = (100.0 - newest.use_percent) / daily_change;
                            if days_until_full < 30.0 {
                                println!(
                                    "  {} Projected full in {:.0} days",
                                    "[!]".red().bold(),
                                    days_until_full
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get inode usage
    fn get_inode_usage(&self, path: Option<&PathBuf>) -> Result<Vec<InodeInfo>> {
        let mut inodes = Vec::new();

        let output = Command::new("df")
            .args(["-i"])
            .output()
            .context("Failed to run df command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let mount = parts[5];

                if let Some(ref p) = path {
                    if !mount.starts_with(&p.to_string_lossy().to_string()) {
                        continue;
                    }
                }

                inodes.push(InodeInfo {
                    filesystem: parts[0].to_string(),
                    total: parts[1].to_string(),
                    used: parts[2].to_string(),
                    available: parts[3].to_string(),
                    use_percent: parts[4].to_string(),
                });
            }
        }

        Ok(inodes)
    }

    /// Check filesystem health
    fn check_health(&self, filesystem: Option<&str>) -> Result<Vec<DiskHealth>> {
        let mut health_reports = Vec::new();

        // Read mount information
        let mounts = fs::read_to_string("/proc/mounts")?;

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let device = parts[0];
                let mount_point = parts[1];
                let fs_type = parts[2];
                let options: Vec<String> = parts[3].split(',').map(|s| s.to_string()).collect();

                if let Some(ref fs) = filesystem {
                    if !mount_point.contains(fs) && !device.contains(fs) {
                        continue;
                    }
                }

                // Skip virtual filesystems
                if fs_type == "proc" || fs_type == "sysfs" || fs_type == "devtmpfs" {
                    continue;
                }

                let is_readonly = options.contains(&"ro".to_string());
                let mut errors = Vec::new();

                // Check for common issues
                if is_readonly && fs_type != "squashfs" {
                    errors.push("Filesystem is mounted read-only".to_string());
                }

                // Check for remount frequency in dmesg (if accessible)
                let dmesg_check = Command::new("dmesg")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();

                if dmesg_check.contains(&format!("{}: I/O error", device)) {
                    errors.push("I/O errors detected in dmesg".to_string());
                }

                health_reports.push(DiskHealth {
                    filesystem: device.to_string(),
                    mount_point: mount_point.to_string(),
                    fs_type: fs_type.to_string(),
                    mount_options: options,
                    is_readonly,
                    errors,
                    smart_status: None,
                });
            }
        }

        Ok(health_reports)
    }

    /// Clean up old files
    fn cleanup(
        &self,
        path: &PathBuf,
        older_than_days: u64,
        patterns: Option<&str>,
        dry_run: bool,
    ) -> Result<(usize, u64)> {
        println!(
            "{} {} files older than {} days in {}",
            if dry_run { "[DRY RUN]".yellow() } else { "[*]".blue() },
            if dry_run { "Would clean" } else { "Cleaning" },
            older_than_days,
            path.display()
        );

        let mut deleted_count = 0usize;
        let mut freed_bytes = 0u64;

        let pattern_list: Vec<&str> = patterns
            .map(|p| p.split(',').collect())
            .unwrap_or_else(|| vec!["*"]);

        // Build find command
        let mut cmd = Command::new("find");
        cmd.arg(path)
            .args(["-type", "f"])
            .args(["-mtime", &format!("+{}", older_than_days)]);

        // Add pattern filters
        if !pattern_list.is_empty() && pattern_list[0] != "*" {
            cmd.arg("(");
            for (i, pattern) in pattern_list.iter().enumerate() {
                if i > 0 {
                    cmd.arg("-o");
                }
                cmd.args(["-name", pattern]);
            }
            cmd.arg(")");
        }

        let output = cmd.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let file_path = PathBuf::from(line.trim());
            if let Ok(metadata) = fs::metadata(&file_path) {
                let size = metadata.len();

                if dry_run {
                    println!("  Would delete: {} ({})", file_path.display(), format_size(size));
                } else {
                    if let Ok(_) = fs::remove_file(&file_path) {
                        println!("  Deleted: {} ({})", file_path.display(), format_size(size));
                        deleted_count += 1;
                        freed_bytes += size;
                    }
                }
            }
        }

        Ok((deleted_count, freed_bytes))
    }

    /// Export disk metrics
    fn export_metrics(&mut self, output: &PathBuf, include_history: bool) -> Result<()> {
        println!("{} Exporting disk metrics...", "[*]".blue());

        let disks = self.get_disk_status(true)?;
        let inodes = self.get_inode_usage(None)?;
        let health = self.check_health(None)?;

        #[derive(Serialize)]
        struct ExportData {
            timestamp: String,
            disks: Vec<DiskInfo>,
            inodes: Vec<InodeInfo>,
            health: Vec<DiskHealth>,
        }

        let data = ExportData {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            disks,
            inodes,
            health,
        };

        let json = serde_json::to_string_pretty(&data)?;
        fs::write(output, json)?;

        println!("{} Metrics exported to {}", "[+]".green(), output.display());
        Ok(())
    }
}

/// Format bytes to human-readable size
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Parse size string to bytes
fn parse_size(size_str: &str) -> Result<u64> {
    let size_str = size_str.trim().to_uppercase();
    let numeric_end = size_str
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(size_str.len());

    let number: f64 = size_str[..numeric_end].parse().unwrap_or(0.0);
    let unit = &size_str[numeric_end..];

    let multiplier: u64 = match unit.trim() {
        "B" | "" => 1,
        "K" | "KB" => 1024,
        "M" | "MB" => 1024 * 1024,
        "G" | "GB" => 1024 * 1024 * 1024,
        "T" | "TB" => 1024 * 1024 * 1024 * 1024,
        _ => 1,
    };

    Ok((number * multiplier as f64) as u64)
}

/// Create a visual usage bar
fn create_usage_bar(percent: u8) -> String {
    let filled = (percent as usize / 5).min(20);
    let empty = 20 - filled;

    let bar_char = if percent >= 90 {
        "#".red()
    } else if percent >= 80 {
        "#".yellow()
    } else {
        "#".green()
    };

    format!(
        "{}{}",
        bar_char.to_string().repeat(filled),
        "-".repeat(empty)
    )
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut monitor = DiskMonitor::new(cli.verbose);

    match cli.command {
        Commands::Status { all } => {
            let disks = monitor.get_disk_status(all)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&disks)?);
            } else {
                println!("{} Disk Usage Status:", "[*]".blue());
                let table = Table::new(&disks).to_string();
                println!("{}", table);
            }
        }

        Commands::Monitor {
            warning,
            critical,
            interval,
            paths,
            alert_method,
            alert_file,
        } => {
            monitor.monitor(
                warning,
                critical,
                interval,
                paths.as_deref(),
                alert_method.as_deref(),
                alert_file.as_ref(),
            )?;
        }

        Commands::FindLarge {
            path,
            size,
            limit,
            hidden,
        } => {
            let files = monitor.find_large_files(&path, &size, limit, hidden)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&files)?);
            } else {
                if files.is_empty() {
                    println!("{} No files found larger than {}", "[*]".yellow(), size);
                } else {
                    println!("{} Found {} large files:", "[+]".green(), files.len());
                    let table = Table::new(&files).to_string();
                    println!("{}", table);
                }
            }
        }

        Commands::DirSize { path, depth, sort } => {
            let dirs = monitor.get_dir_sizes(&path, depth, sort)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&dirs)?);
            } else {
                let table = Table::new(&dirs).to_string();
                println!("{}", table);
            }
        }

        Commands::Trends {
            data_file,
            days,
            record,
        } => {
            if record {
                monitor.record_trends(&data_file)?;
            } else {
                monitor.show_trends(&data_file, days)?;
            }
        }

        Commands::Inodes { path } => {
            let inodes = monitor.get_inode_usage(path.as_ref())?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&inodes)?);
            } else {
                println!("{} Inode Usage:", "[*]".blue());
                let table = Table::new(&inodes).to_string();
                println!("{}", table);
            }
        }

        Commands::Health { filesystem } => {
            let health = monitor.check_health(filesystem.as_deref())?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&health)?);
            } else {
                println!("{} Filesystem Health Report:", "[*]".blue());
                println!("{}", "=".repeat(70));

                for h in &health {
                    let status = if h.errors.is_empty() {
                        "OK".green()
                    } else {
                        "ISSUES".red()
                    };

                    println!(
                        "\n  {} {} ({})",
                        status,
                        h.filesystem,
                        h.fs_type
                    );
                    println!("    Mount: {}", h.mount_point);
                    println!("    Read-only: {}", h.is_readonly);

                    if !h.errors.is_empty() {
                        println!("    Errors:");
                        for error in &h.errors {
                            println!("      - {}", error.red());
                        }
                    }
                }
            }
        }

        Commands::ConfigAlert {
            email,
            webhook,
            save,
            config,
        } => {
            let config_data = AlertConfig {
                email,
                webhook,
                warning_threshold: 80,
                critical_threshold: 90,
            };

            if save {
                let json = serde_json::to_string_pretty(&config_data)?;
                fs::write(&config, json)?;
                println!("{} Configuration saved to {}", "[+]".green(), config.display());
            } else {
                println!("{}", serde_json::to_string_pretty(&config_data)?);
            }
        }

        Commands::Export { output, history } => {
            monitor.export_metrics(&output, history)?;
        }

        Commands::Cleanup {
            path,
            older_than,
            patterns,
            dry_run,
        } => {
            let (count, freed) = monitor.cleanup(&path, older_than, patterns.as_deref(), dry_run)?;

            if dry_run {
                println!(
                    "{} Would delete {} files, freeing {}",
                    "[*]".yellow(),
                    count,
                    format_size(freed)
                );
            } else {
                println!(
                    "{} Deleted {} files, freed {}",
                    "[+]".green(),
                    count,
                    format_size(freed)
                );
            }
        }
    }

    Ok(())
}
