//! AU01 Service Manager - System Service Management Tool
//!
//! This tool provides comprehensive service management capabilities for Linux systems.
//! It can start, stop, restart, enable, disable, and monitor system services.
//!
//! Features:
//! - List all services with their current status
//! - Start/stop/restart individual services
//! - Enable/disable services at boot
//! - Monitor service health and resource usage
//! - Service dependency analysis
//! - Batch operations on multiple services
//!
//! Security applications:
//! - Ensure critical security services are running
//! - Disable unnecessary services to reduce attack surface
//! - Monitor for unauthorized service changes
//! - Automate incident response service management

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use sysinfo::{Pid, System};
use tabled::{Table, Tabled};

/// Service Manager - Comprehensive system service management tool
#[derive(Parser)]
#[command(name = "service-manager")]
#[command(author = "Security Engineer")]
#[command(version = "1.0")]
#[command(about = "Manage and monitor system services for security operations")]
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
    /// List all services or filter by status
    List {
        /// Filter by status (running, stopped, all)
        #[arg(short, long, default_value = "all")]
        status: String,

        /// Filter by name pattern
        #[arg(short, long)]
        pattern: Option<String>,
    },

    /// Start a service
    Start {
        /// Service name
        name: String,

        /// Wait for service to fully start
        #[arg(short, long)]
        wait: bool,
    },

    /// Stop a service
    Stop {
        /// Service name
        name: String,

        /// Force stop (SIGKILL)
        #[arg(short, long)]
        force: bool,
    },

    /// Restart a service
    Restart {
        /// Service name
        name: String,
    },

    /// Enable service at boot
    Enable {
        /// Service name
        name: String,
    },

    /// Disable service at boot
    Disable {
        /// Service name
        name: String,
    },

    /// Get detailed status of a service
    Status {
        /// Service name
        name: String,
    },

    /// Monitor services in real-time
    Monitor {
        /// Services to monitor (comma-separated)
        #[arg(short, long)]
        services: Option<String>,

        /// Refresh interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,

        /// Alert on status change
        #[arg(short, long)]
        alert: bool,
    },

    /// Analyze service dependencies
    Dependencies {
        /// Service name
        name: String,

        /// Show reverse dependencies (what depends on this)
        #[arg(short, long)]
        reverse: bool,
    },

    /// Check security-critical services
    SecurityCheck {
        /// Custom list of critical services
        #[arg(short, long)]
        services: Option<String>,
    },

    /// Export service configuration
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Batch operations from config file
    Batch {
        /// Config file with operations
        config: PathBuf,
    },
}

/// Represents a system service
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct Service {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Enabled")]
    enabled: String,
    #[tabled(rename = "PID")]
    pid: String,
    #[tabled(rename = "Memory")]
    memory: String,
    #[tabled(rename = "Description")]
    #[tabled(display_with = "truncate_description")]
    description: String,
}

/// Truncate description for table display
fn truncate_description(desc: &String) -> String {
    if desc.len() > 40 {
        format!("{}...", &desc[..37])
    } else {
        desc.clone()
    }
}

/// Detailed service information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceDetails {
    name: String,
    status: String,
    enabled: bool,
    pid: Option<u32>,
    main_pid: Option<u32>,
    memory_usage: Option<u64>,
    cpu_usage: Option<f32>,
    uptime: Option<String>,
    description: String,
    unit_file: Option<String>,
    dependencies: Vec<String>,
    required_by: Vec<String>,
    last_log_entries: Vec<String>,
}

/// Batch operation configuration
#[derive(Debug, Deserialize)]
struct BatchConfig {
    operations: Vec<BatchOperation>,
}

#[derive(Debug, Deserialize)]
struct BatchOperation {
    action: String,
    service: String,
    #[serde(default)]
    wait: bool,
}

/// Service manager implementation
struct ServiceManager {
    system: System,
    verbose: bool,
}

impl ServiceManager {
    /// Create a new service manager
    fn new(verbose: bool) -> Self {
        Self {
            system: System::new_all(),
            verbose,
        }
    }

    /// List all services matching the criteria
    fn list_services(&mut self, status_filter: &str, pattern: Option<&str>) -> Result<Vec<Service>> {
        let mut services = Vec::new();

        // Get list of all systemd units
        let output = Command::new("systemctl")
            .args(["list-units", "--type=service", "--all", "--no-pager", "--plain"])
            .output()
            .context("Failed to execute systemctl")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let unit_name = parts[0].trim_end_matches(".service");
            let _load = parts[1];
            let active = parts[2];
            let sub = parts[3];
            let description = parts[4..].join(" ");

            // Apply filters
            if let Some(pat) = pattern {
                if !unit_name.contains(pat) {
                    continue;
                }
            }

            let status_str = format!("{}/{}", active, sub);
            match status_filter {
                "running" => {
                    if active != "active" || sub != "running" {
                        continue;
                    }
                }
                "stopped" => {
                    if active == "active" {
                        continue;
                    }
                }
                _ => {}
            }

            // Get enabled status
            let enabled = self.is_service_enabled(unit_name)?;

            // Get PID and memory if running
            let (pid, memory) = if sub == "running" {
                self.get_service_process_info(unit_name)
            } else {
                (String::from("-"), String::from("-"))
            };

            services.push(Service {
                name: unit_name.to_string(),
                status: status_str,
                enabled: if enabled {
                    "Yes".to_string()
                } else {
                    "No".to_string()
                },
                pid,
                memory,
                description,
            });
        }

        Ok(services)
    }

    /// Check if a service is enabled
    fn is_service_enabled(&self, name: &str) -> Result<bool> {
        let output = Command::new("systemctl")
            .args(["is-enabled", &format!("{}.service", name)])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim() == "enabled")
    }

    /// Get process information for a service
    fn get_service_process_info(&mut self, name: &str) -> (String, String) {
        // Get main PID
        let output = Command::new("systemctl")
            .args(["show", "-p", "MainPID", &format!("{}.service", name)])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(pid_str) = stdout.strip_prefix("MainPID=") {
                if let Ok(pid) = pid_str.trim().parse::<usize>() {
                    if pid > 0 {
                        self.system.refresh_all();
                        if let Some(process) = self.system.process(Pid::from(pid)) {
                            let memory_mb = process.memory() / 1024 / 1024;
                            return (pid.to_string(), format!("{} MB", memory_mb));
                        }
                        return (pid.to_string(), "-".to_string());
                    }
                }
            }
        }

        ("-".to_string(), "-".to_string())
    }

    /// Start a service
    fn start_service(&self, name: &str, wait: bool) -> Result<()> {
        println!("{} Starting service: {}", "[*]".blue(), name.cyan());

        let mut cmd = Command::new("systemctl");
        cmd.args(["start", &format!("{}.service", name)]);

        if wait {
            cmd.arg("--wait");
        }

        let output = cmd.output().context("Failed to start service")?;

        if output.status.success() {
            println!("{} Service {} started successfully", "[+]".green(), name.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to start service: {}", stderr);
        }
    }

    /// Stop a service
    fn stop_service(&self, name: &str, force: bool) -> Result<()> {
        println!("{} Stopping service: {}", "[*]".blue(), name.cyan());

        let output = if force {
            Command::new("systemctl")
                .args(["kill", "-s", "SIGKILL", &format!("{}.service", name)])
                .output()
                .context("Failed to kill service")?
        } else {
            Command::new("systemctl")
                .args(["stop", &format!("{}.service", name)])
                .output()
                .context("Failed to stop service")?
        };

        if output.status.success() {
            println!("{} Service {} stopped successfully", "[+]".green(), name.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to stop service: {}", stderr);
        }
    }

    /// Restart a service
    fn restart_service(&self, name: &str) -> Result<()> {
        println!("{} Restarting service: {}", "[*]".blue(), name.cyan());

        let output = Command::new("systemctl")
            .args(["restart", &format!("{}.service", name)])
            .output()
            .context("Failed to restart service")?;

        if output.status.success() {
            println!("{} Service {} restarted successfully", "[+]".green(), name.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to restart service: {}", stderr);
        }
    }

    /// Enable a service at boot
    fn enable_service(&self, name: &str) -> Result<()> {
        println!("{} Enabling service: {}", "[*]".blue(), name.cyan());

        let output = Command::new("systemctl")
            .args(["enable", &format!("{}.service", name)])
            .output()
            .context("Failed to enable service")?;

        if output.status.success() {
            println!("{} Service {} enabled at boot", "[+]".green(), name.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to enable service: {}", stderr);
        }
    }

    /// Disable a service at boot
    fn disable_service(&self, name: &str) -> Result<()> {
        println!("{} Disabling service: {}", "[*]".blue(), name.cyan());

        let output = Command::new("systemctl")
            .args(["disable", &format!("{}.service", name)])
            .output()
            .context("Failed to disable service")?;

        if output.status.success() {
            println!("{} Service {} disabled at boot", "[+]".green(), name.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to disable service: {}", stderr);
        }
    }

    /// Get detailed service status
    fn get_service_details(&mut self, name: &str) -> Result<ServiceDetails> {
        // Get basic status
        let status_output = Command::new("systemctl")
            .args(["show", &format!("{}.service", name)])
            .output()
            .context("Failed to get service status")?;

        let status_str = String::from_utf8_lossy(&status_output.stdout);
        let mut properties: HashMap<String, String> = HashMap::new();

        for line in status_str.lines() {
            if let Some((key, value)) = line.split_once('=') {
                properties.insert(key.to_string(), value.to_string());
            }
        }

        let active_state = properties
            .get("ActiveState")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let sub_state = properties
            .get("SubState")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let main_pid = properties
            .get("MainPID")
            .and_then(|p| p.parse().ok())
            .filter(|&p: &u32| p > 0);

        let enabled = properties
            .get("UnitFileState")
            .map(|s| s == "enabled")
            .unwrap_or(false);

        // Get memory and CPU usage if running
        let (memory_usage, cpu_usage) = if let Some(pid) = main_pid {
            self.system.refresh_all();
            if let Some(process) = self.system.process(Pid::from(pid as usize)) {
                (Some(process.memory()), Some(process.cpu_usage()))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Get dependencies
        let deps_output = Command::new("systemctl")
            .args(["list-dependencies", &format!("{}.service", name), "--plain"])
            .output()?;
        let deps_str = String::from_utf8_lossy(&deps_output.stdout);
        let dependencies: Vec<String> = deps_str
            .lines()
            .skip(1)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Get reverse dependencies
        let rdeps_output = Command::new("systemctl")
            .args([
                "list-dependencies",
                &format!("{}.service", name),
                "--reverse",
                "--plain",
            ])
            .output()?;
        let rdeps_str = String::from_utf8_lossy(&rdeps_output.stdout);
        let required_by: Vec<String> = rdeps_str
            .lines()
            .skip(1)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Get recent log entries
        let log_output = Command::new("journalctl")
            .args(["-u", &format!("{}.service", name), "-n", "5", "--no-pager"])
            .output()?;
        let log_str = String::from_utf8_lossy(&log_output.stdout);
        let last_log_entries: Vec<String> = log_str.lines().map(|s| s.to_string()).collect();

        Ok(ServiceDetails {
            name: name.to_string(),
            status: format!("{}/{}", active_state, sub_state),
            enabled,
            pid: main_pid,
            main_pid,
            memory_usage,
            cpu_usage,
            uptime: properties.get("ActiveEnterTimestamp").cloned(),
            description: properties
                .get("Description")
                .cloned()
                .unwrap_or_default(),
            unit_file: properties.get("FragmentPath").cloned(),
            dependencies,
            required_by,
            last_log_entries,
        })
    }

    /// Monitor services in real-time
    fn monitor_services(
        &mut self,
        services: Option<&str>,
        interval: u64,
        alert: bool,
    ) -> Result<()> {
        let service_list: Vec<String> = if let Some(svcs) = services {
            svcs.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            // Monitor all running services
            vec![]
        };

        let mut previous_status: HashMap<String, String> = HashMap::new();

        println!("{} Starting service monitor (Ctrl+C to stop)", "[*]".blue());
        println!("{}", "=".repeat(80));

        loop {
            // Clear screen for fresh display
            print!("\x1B[2J\x1B[1;1H");

            let now: DateTime<Local> = Local::now();
            println!(
                "{} Service Monitor - {}",
                "[*]".blue(),
                now.format("%Y-%m-%d %H:%M:%S")
            );
            println!("{}", "=".repeat(80));

            let services_to_check = if service_list.is_empty() {
                self.list_services("running", None)?
                    .iter()
                    .map(|s| s.name.clone())
                    .collect()
            } else {
                service_list.clone()
            };

            for service_name in &services_to_check {
                match self.get_service_details(service_name) {
                    Ok(details) => {
                        let status_color = if details.status.contains("running") {
                            details.status.green()
                        } else if details.status.contains("failed") {
                            details.status.red()
                        } else {
                            details.status.yellow()
                        };

                        let memory_str = details
                            .memory_usage
                            .map(|m| format!("{:.1} MB", m as f64 / 1024.0 / 1024.0))
                            .unwrap_or_else(|| "-".to_string());

                        let cpu_str = details
                            .cpu_usage
                            .map(|c| format!("{:.1}%", c))
                            .unwrap_or_else(|| "-".to_string());

                        println!(
                            "  {} {} | PID: {} | Mem: {} | CPU: {}",
                            service_name.cyan(),
                            status_color,
                            details.pid.map(|p| p.to_string()).unwrap_or("-".to_string()),
                            memory_str,
                            cpu_str
                        );

                        // Check for status changes
                        if alert {
                            if let Some(prev_status) = previous_status.get(service_name) {
                                if prev_status != &details.status {
                                    println!(
                                        "  {} ALERT: {} status changed from {} to {}",
                                        "[!]".red().bold(),
                                        service_name,
                                        prev_status,
                                        details.status
                                    );
                                }
                            }
                            previous_status.insert(service_name.clone(), details.status);
                        }
                    }
                    Err(e) => {
                        println!("  {} {} - Error: {}", service_name.cyan(), "UNKNOWN".red(), e);
                    }
                }
            }

            println!("{}", "=".repeat(80));
            println!("Refresh interval: {}s | Monitoring {} services", interval, services_to_check.len());

            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
    }

    /// Check security-critical services
    fn security_check(&mut self, custom_services: Option<&str>) -> Result<()> {
        let default_critical = vec![
            "firewalld",
            "iptables",
            "ufw",
            "fail2ban",
            "sshd",
            "auditd",
            "rsyslog",
            "systemd-journald",
            "apparmor",
            "selinux",
            "clamav-daemon",
            "rkhunter",
        ];

        let services_to_check: Vec<&str> = if let Some(custom) = custom_services {
            custom.split(',').map(|s| s.trim()).collect()
        } else {
            default_critical
        };

        println!("{} Security Service Check", "[*]".blue().bold());
        println!("{}", "=".repeat(60));

        let mut issues = Vec::new();

        for service in &services_to_check {
            let status = self.check_service_exists_and_status(service);
            match status {
                ServiceCheckResult::Running => {
                    println!("  {} {} - {}", "[+]".green(), service, "Running".green());
                }
                ServiceCheckResult::Stopped => {
                    println!("  {} {} - {}", "[-]".yellow(), service, "Stopped".yellow());
                    issues.push(format!("{} is stopped", service));
                }
                ServiceCheckResult::Failed => {
                    println!("  {} {} - {}", "[!]".red(), service, "Failed".red());
                    issues.push(format!("{} has failed", service));
                }
                ServiceCheckResult::NotFound => {
                    println!("  {} {} - {}", "[?]".white(), service, "Not installed".white());
                }
            }
        }

        println!("{}", "=".repeat(60));

        if issues.is_empty() {
            println!(
                "{} All checked security services are running properly",
                "[+]".green().bold()
            );
        } else {
            println!(
                "{} Found {} issues:",
                "[!]".red().bold(),
                issues.len()
            );
            for issue in &issues {
                println!("  - {}", issue.red());
            }
        }

        Ok(())
    }

    /// Check if a service exists and get its status
    fn check_service_exists_and_status(&self, name: &str) -> ServiceCheckResult {
        let output = Command::new("systemctl")
            .args(["is-active", &format!("{}.service", name)])
            .output();

        match output {
            Ok(out) => {
                let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match status.as_str() {
                    "active" => ServiceCheckResult::Running,
                    "inactive" => ServiceCheckResult::Stopped,
                    "failed" => ServiceCheckResult::Failed,
                    _ => ServiceCheckResult::NotFound,
                }
            }
            Err(_) => ServiceCheckResult::NotFound,
        }
    }

    /// Export service configuration
    fn export_config(&mut self, output: &PathBuf) -> Result<()> {
        println!("{} Exporting service configuration...", "[*]".blue());

        let services = self.list_services("all", None)?;
        let json = serde_json::to_string_pretty(&services)?;

        fs::write(output, json)?;
        println!(
            "{} Configuration exported to {}",
            "[+]".green(),
            output.display()
        );

        Ok(())
    }

    /// Execute batch operations
    fn batch_operations(&self, config_path: &PathBuf) -> Result<()> {
        println!("{} Loading batch configuration...", "[*]".blue());

        let config_str = fs::read_to_string(config_path)
            .context("Failed to read batch config")?;
        let config: BatchConfig = serde_json::from_str(&config_str)
            .context("Failed to parse batch config")?;

        println!(
            "{} Executing {} operations...",
            "[*]".blue(),
            config.operations.len()
        );

        for op in &config.operations {
            println!("\n{} {} -> {}", "[*]".blue(), op.action, op.service);

            let result = match op.action.as_str() {
                "start" => self.start_service(&op.service, op.wait),
                "stop" => self.stop_service(&op.service, false),
                "restart" => self.restart_service(&op.service),
                "enable" => self.enable_service(&op.service),
                "disable" => self.disable_service(&op.service),
                _ => {
                    println!("  {} Unknown action: {}", "[!]".yellow(), op.action);
                    continue;
                }
            };

            if let Err(e) = result {
                println!("  {} Failed: {}", "[!]".red(), e);
            }
        }

        println!("\n{} Batch operations completed", "[+]".green());
        Ok(())
    }
}

/// Service check result
enum ServiceCheckResult {
    Running,
    Stopped,
    Failed,
    NotFound,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut manager = ServiceManager::new(cli.verbose);

    match cli.command {
        Commands::List { status, pattern } => {
            let services = manager.list_services(&status, pattern.as_deref())?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&services)?);
            } else {
                if services.is_empty() {
                    println!("{} No services found matching criteria", "[*]".yellow());
                } else {
                    println!("{} Found {} services:", "[+]".green(), services.len());
                    let table = Table::new(&services).to_string();
                    println!("{}", table);
                }
            }
        }

        Commands::Start { name, wait } => {
            manager.start_service(&name, wait)?;
        }

        Commands::Stop { name, force } => {
            manager.stop_service(&name, force)?;
        }

        Commands::Restart { name } => {
            manager.restart_service(&name)?;
        }

        Commands::Enable { name } => {
            manager.enable_service(&name)?;
        }

        Commands::Disable { name } => {
            manager.disable_service(&name)?;
        }

        Commands::Status { name } => {
            let details = manager.get_service_details(&name)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&details)?);
            } else {
                println!("{} Service: {}", "[*]".blue(), details.name.cyan().bold());
                println!("{}", "=".repeat(50));
                println!("  Status:      {}", details.status);
                println!("  Enabled:     {}", details.enabled);
                println!(
                    "  PID:         {}",
                    details.pid.map(|p| p.to_string()).unwrap_or("-".to_string())
                );
                println!(
                    "  Memory:      {}",
                    details
                        .memory_usage
                        .map(|m| format!("{:.1} MB", m as f64 / 1024.0 / 1024.0))
                        .unwrap_or("-".to_string())
                );
                println!(
                    "  CPU:         {}",
                    details
                        .cpu_usage
                        .map(|c| format!("{:.1}%", c))
                        .unwrap_or("-".to_string())
                );
                println!("  Description: {}", details.description);
                println!(
                    "  Unit File:   {}",
                    details.unit_file.unwrap_or("-".to_string())
                );

                if !details.dependencies.is_empty() {
                    println!("\n  Dependencies ({}):", details.dependencies.len());
                    for dep in details.dependencies.iter().take(5) {
                        println!("    - {}", dep);
                    }
                    if details.dependencies.len() > 5 {
                        println!("    ... and {} more", details.dependencies.len() - 5);
                    }
                }

                if !details.last_log_entries.is_empty() {
                    println!("\n  Recent Log Entries:");
                    for entry in &details.last_log_entries {
                        println!("    {}", entry);
                    }
                }
            }
        }

        Commands::Monitor {
            services,
            interval,
            alert,
        } => {
            manager.monitor_services(services.as_deref(), interval, alert)?;
        }

        Commands::Dependencies { name, reverse } => {
            let cmd = if reverse {
                vec![
                    "list-dependencies",
                    &format!("{}.service", name),
                    "--reverse",
                ]
            } else {
                vec!["list-dependencies", &format!("{}.service", name)]
            };

            let output = Command::new("systemctl")
                .args(&cmd)
                .output()
                .context("Failed to get dependencies")?;

            println!("{}", String::from_utf8_lossy(&output.stdout));
        }

        Commands::SecurityCheck { services } => {
            manager.security_check(services.as_deref())?;
        }

        Commands::Export { output } => {
            manager.export_config(&output)?;
        }

        Commands::Batch { config } => {
            manager.batch_operations(&config)?;
        }
    }

    Ok(())
}
