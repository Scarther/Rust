# System Automation in Rust

## Overview

Automate repetitive system administration and security tasks with Rust. Build tools that are fast, reliable, and cross-platform.

---

## Learning Objectives

- Execute system commands from Rust
- Manage files and directories programmatically
- Schedule and monitor tasks
- Build cross-platform automation tools
- Handle errors gracefully in automation scripts

---

## Command Execution

### Basic Command Execution

```rust
use std::process::Command;

fn main() {
    // Simple command
    let output = Command::new("ls")
        .arg("-la")
        .output()
        .expect("Failed to execute command");

    println!("Status: {}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
}
```

### With Environment Variables

```rust
use std::process::Command;
use std::collections::HashMap;

fn run_with_env(cmd: &str, args: &[&str], env: HashMap<&str, &str>) -> Result<String, String> {
    let mut command = Command::new(cmd);
    command.args(args);

    for (key, value) in env {
        command.env(key, value);
    }

    let output = command.output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn main() {
    let mut env = HashMap::new();
    env.insert("MY_VAR", "test_value");

    match run_with_env("printenv", &["MY_VAR"], env) {
        Ok(output) => println!("Output: {}", output),
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

### Async Command Execution

```rust
use tokio::process::Command;

#[tokio::main]
async fn main() {
    let output = Command::new("sleep")
        .arg("2")
        .output()
        .await
        .expect("Failed to execute command");

    println!("Command completed with status: {}", output.status);
}
```

---

## File Operations

### Batch File Processor

```rust
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;

struct FileProcessor {
    source_dir: String,
    processed: usize,
    errors: Vec<String>,
}

impl FileProcessor {
    fn new(source_dir: &str) -> Self {
        Self {
            source_dir: source_dir.to_string(),
            processed: 0,
            errors: Vec::new(),
        }
    }

    fn process_all<F>(&mut self, processor: F)
    where
        F: Fn(&Path) -> Result<(), String>,
    {
        for entry in WalkDir::new(&self.source_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            match processor(entry.path()) {
                Ok(_) => self.processed += 1,
                Err(e) => self.errors.push(format!("{}: {}", entry.path().display(), e)),
            }
        }
    }

    fn report(&self) {
        println!("Processed: {} files", self.processed);
        println!("Errors: {}", self.errors.len());

        if !self.errors.is_empty() {
            println!("\nError details:");
            for err in &self.errors {
                println!("  {}", err);
            }
        }
    }
}

// Example: Find files containing sensitive data
fn scan_for_secrets(path: &Path) -> Result<(), String> {
    let mut content = String::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .read_to_string(&mut content)
        .map_err(|e| e.to_string())?;

    let patterns = [
        "password", "secret", "api_key", "private_key",
        "AWS_ACCESS_KEY", "GITHUB_TOKEN",
    ];

    for pattern in patterns {
        if content.to_lowercase().contains(&pattern.to_lowercase()) {
            println!("[!] Found '{}' in {}", pattern, path.display());
        }
    }

    Ok(())
}

fn main() {
    let mut processor = FileProcessor::new("/tmp/test");
    processor.process_all(scan_for_secrets);
    processor.report();
}
```

### Backup Utility

```rust
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use chrono::Local;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;

struct BackupConfig {
    source_dirs: Vec<PathBuf>,
    destination: PathBuf,
    compress: bool,
    exclude_patterns: Vec<String>,
}

fn create_backup(config: &BackupConfig) -> Result<PathBuf, String> {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = if config.compress {
        format!("backup_{}.tar.gz", timestamp)
    } else {
        format!("backup_{}.tar", timestamp)
    };

    let backup_path = config.destination.join(&filename);

    let file = File::create(&backup_path)
        .map_err(|e| format!("Cannot create backup file: {}", e))?;

    if config.compress {
        let encoder = GzEncoder::new(file, Compression::default());
        let mut archive = Builder::new(encoder);

        for dir in &config.source_dirs {
            archive.append_dir_all(
                dir.file_name().unwrap_or_default(),
                dir
            ).map_err(|e| e.to_string())?;
        }

        archive.finish().map_err(|e| e.to_string())?;
    }

    Ok(backup_path)
}

fn main() {
    let config = BackupConfig {
        source_dirs: vec![
            PathBuf::from("/etc/nginx"),
            PathBuf::from("/var/www"),
        ],
        destination: PathBuf::from("/backups"),
        compress: true,
        exclude_patterns: vec!["*.log".to_string(), "*.tmp".to_string()],
    };

    match create_backup(&config) {
        Ok(path) => println!("Backup created: {}", path.display()),
        Err(e) => eprintln!("Backup failed: {}", e),
    }
}
```

---

## System Monitoring

### Health Checker

```rust
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct HealthCheck {
    name: String,
    status: HealthStatus,
    duration: Duration,
    message: String,
}

#[derive(Debug)]
enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

fn check_disk_space() -> HealthCheck {
    let start = Instant::now();

    let output = Command::new("df")
        .arg("-h")
        .arg("/")
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse disk usage percentage
            let usage: u8 = stdout.lines()
                .nth(1)
                .and_then(|line| line.split_whitespace().nth(4))
                .and_then(|pct| pct.trim_end_matches('%').parse().ok())
                .unwrap_or(0);

            let status = match usage {
                0..=70 => HealthStatus::Healthy,
                71..=90 => HealthStatus::Warning,
                _ => HealthStatus::Critical,
            };

            HealthCheck {
                name: "Disk Space".to_string(),
                status,
                duration: start.elapsed(),
                message: format!("{}% used", usage),
            }
        }
        Err(e) => HealthCheck {
            name: "Disk Space".to_string(),
            status: HealthStatus::Critical,
            duration: start.elapsed(),
            message: format!("Check failed: {}", e),
        },
    }
}

fn check_memory() -> HealthCheck {
    let start = Instant::now();

    let output = Command::new("free")
        .arg("-m")
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse memory usage
            let mem_line = stdout.lines().nth(1).unwrap_or("");
            let parts: Vec<&str> = mem_line.split_whitespace().collect();

            if parts.len() >= 3 {
                let total: u64 = parts[1].parse().unwrap_or(1);
                let used: u64 = parts[2].parse().unwrap_or(0);
                let pct = (used * 100) / total;

                let status = match pct {
                    0..=70 => HealthStatus::Healthy,
                    71..=90 => HealthStatus::Warning,
                    _ => HealthStatus::Critical,
                };

                HealthCheck {
                    name: "Memory".to_string(),
                    status,
                    duration: start.elapsed(),
                    message: format!("{}% used ({}/{}MB)", pct, used, total),
                }
            } else {
                HealthCheck {
                    name: "Memory".to_string(),
                    status: HealthStatus::Warning,
                    duration: start.elapsed(),
                    message: "Could not parse memory info".to_string(),
                }
            }
        }
        Err(e) => HealthCheck {
            name: "Memory".to_string(),
            status: HealthStatus::Critical,
            duration: start.elapsed(),
            message: format!("Check failed: {}", e),
        },
    }
}

fn check_service(service_name: &str) -> HealthCheck {
    let start = Instant::now();

    let output = Command::new("systemctl")
        .arg("is-active")
        .arg(service_name)
        .output();

    match output {
        Ok(out) => {
            let active = String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_lowercase() == "active";

            HealthCheck {
                name: format!("Service: {}", service_name),
                status: if active { HealthStatus::Healthy } else { HealthStatus::Critical },
                duration: start.elapsed(),
                message: if active { "Running".to_string() } else { "Not running".to_string() },
            }
        }
        Err(e) => HealthCheck {
            name: format!("Service: {}", service_name),
            status: HealthStatus::Critical,
            duration: start.elapsed(),
            message: format!("Check failed: {}", e),
        },
    }
}

fn main() {
    println!("=== System Health Check ===\n");

    let checks = vec![
        check_disk_space(),
        check_memory(),
        check_service("sshd"),
        check_service("nginx"),
    ];

    for check in &checks {
        let status_icon = match check.status {
            HealthStatus::Healthy => "[OK]",
            HealthStatus::Warning => "[WARN]",
            HealthStatus::Critical => "[CRIT]",
        };

        println!("{} {} - {} ({:?})",
            status_icon,
            check.name,
            check.message,
            check.duration
        );
    }

    // Exit with error code if any critical
    let has_critical = checks.iter()
        .any(|c| matches!(c.status, HealthStatus::Critical));

    if has_critical {
        std::process::exit(1);
    }
}
```

---

## Scheduled Tasks

### Simple Scheduler

```rust
use std::thread;
use std::time::Duration;
use chrono::{Local, Timelike};

struct ScheduledTask {
    name: String,
    interval: Duration,
    action: Box<dyn Fn() + Send>,
}

fn run_scheduler(tasks: Vec<ScheduledTask>) {
    let mut handles = Vec::new();

    for task in tasks {
        let handle = thread::spawn(move || {
            loop {
                println!("[{}] Running task: {}",
                    Local::now().format("%H:%M:%S"),
                    task.name
                );

                (task.action)();

                thread::sleep(task.interval);
            }
        });

        handles.push(handle);
    }

    // Wait for all tasks (they run forever)
    for handle in handles {
        let _ = handle.join();
    }
}

fn main() {
    let tasks = vec![
        ScheduledTask {
            name: "Health Check".to_string(),
            interval: Duration::from_secs(60),
            action: Box::new(|| {
                println!("  Performing health check...");
            }),
        },
        ScheduledTask {
            name: "Log Rotation".to_string(),
            interval: Duration::from_secs(3600),
            action: Box::new(|| {
                println!("  Rotating logs...");
            }),
        },
    ];

    println!("Starting scheduler with {} tasks", tasks.len());
    run_scheduler(tasks);
}
```

---

## Complete Automation Tool

```rust
use std::process::Command;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use chrono::Local;

struct AutomationRunner {
    log_file: Option<File>,
    verbose: bool,
}

impl AutomationRunner {
    fn new(log_path: Option<&str>, verbose: bool) -> Self {
        let log_file = log_path.and_then(|p| File::create(p).ok());

        Self { log_file, verbose }
    }

    fn log(&mut self, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = format!("[{}] {}", timestamp, message);

        if self.verbose {
            println!("{}", line);
        }

        if let Some(ref mut file) = self.log_file {
            let _ = writeln!(file, "{}", line);
        }
    }

    fn run_command(&mut self, cmd: &str, args: &[&str]) -> Result<String, String> {
        self.log(&format!("Running: {} {}", cmd, args.join(" ")));

        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute: {}", e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            self.log("Command succeeded");
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            self.log(&format!("Command failed: {}", stderr));
            Err(stderr)
        }
    }

    fn copy_file(&mut self, src: &str, dst: &str) -> Result<(), String> {
        self.log(&format!("Copying {} to {}", src, dst));

        fs::copy(src, dst)
            .map_err(|e| format!("Copy failed: {}", e))?;

        self.log("Copy succeeded");
        Ok(())
    }

    fn create_directory(&mut self, path: &str) -> Result<(), String> {
        if Path::new(path).exists() {
            self.log(&format!("Directory exists: {}", path));
            return Ok(());
        }

        self.log(&format!("Creating directory: {}", path));

        fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create directory: {}", e))?;

        self.log("Directory created");
        Ok(())
    }
}

fn main() {
    let mut runner = AutomationRunner::new(
        Some("/tmp/automation.log"),
        true
    );

    println!("=== Server Setup Automation ===\n");

    // Create directories
    let dirs = ["/tmp/app", "/tmp/app/logs", "/tmp/app/config"];
    for dir in dirs {
        if let Err(e) = runner.create_directory(dir) {
            eprintln!("Error: {}", e);
        }
    }

    // Run system commands
    if let Err(e) = runner.run_command("ls", &["-la", "/tmp/app"]) {
        eprintln!("Error: {}", e);
    }

    println!("\nAutomation complete!");
}
```

---

## Exercises

1. **Deploy Script**: Create a deployment automation tool
2. **Config Manager**: Sync configuration files across servers
3. **Cleanup Tool**: Remove old logs and temp files
4. **Service Monitor**: Restart services if they crash

---

## Key Takeaways

1. **Command execution** - Use `std::process::Command`
2. **Error handling is critical** - Automation must handle failures
3. **Logging everything** - Essential for debugging
4. **Cross-platform** - Consider Windows vs Linux differences
5. **Idempotency** - Running twice should be safe

---

[← Back to Automation](./README.md)
