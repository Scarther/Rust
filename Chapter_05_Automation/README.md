# Chapter 5: Automation Mastery

## Overview

Automate system administration, network operations, and DevOps tasks with Rust.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AUTOMATION DOMAINS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │  SYSTEM ADMIN   │  │    NETWORK      │  │    FILE OPS     │             │
│  │  ─────────────  │  │  ───────────    │  │  ───────────    │             │
│  │  • Services     │  │  • Config mgmt  │  │  • Batch process│             │
│  │  • Users        │  │  • Monitoring   │  │  • Transform    │             │
│  │  • Backups      │  │  • Traffic      │  │  • Reports      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │     DEVOPS      │  │   SCHEDULED     │  │   MONITORING    │             │
│  │  ─────────────  │  │  ───────────    │  │  ───────────    │             │
│  │  • CI/CD        │  │  • Cron jobs    │  │  • Health check │             │
│  │  • Containers   │  │  • Timers       │  │  • Alerting     │             │
│  │  • IaC          │  │  • Triggers     │  │  • Dashboards   │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Sections

| Section | Focus | Projects |
|---------|-------|----------|
| [01_System_Admin](01_System_Admin/) | System management | Service control, user management |
| [02_Network](02_Network/) | Network automation | Config management, monitoring |
| [03_File_Processing](03_File_Processing/) | Batch file operations | Transform, analyze, report |
| [04_DevOps](04_DevOps/) | CI/CD and containers | Docker, pipelines, secrets |

## Key Projects

### A01: Service Manager
Cross-platform service control:

```rust
use std::process::Command;

enum ServiceAction { Start, Stop, Restart, Status }

struct ServiceManager {
    name: String,
}

impl ServiceManager {
    fn execute(&self, action: ServiceAction) -> Result<String, String> {
        let (cmd, args) = match std::env::consts::OS {
            "linux" => ("systemctl", vec![action.to_str(), &self.name]),
            "windows" => ("sc", vec![action.to_str(), &self.name]),
            "macos" => ("launchctl", vec![action.to_str(), &self.name]),
            _ => return Err("Unsupported OS".to_string()),
        };

        let output = Command::new(cmd)
            .args(&args)
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
}

impl ServiceAction {
    fn to_str(&self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Status => "status",
        }
    }
}
```

### A02: Backup Automation
Scheduled backup with rotation:

```rust
use std::fs;
use std::path::Path;
use chrono::Local;

struct BackupManager {
    source: String,
    destination: String,
    retention_days: u32,
}

impl BackupManager {
    fn create_backup(&self) -> Result<String, std::io::Error> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let backup_name = format!("backup_{}.tar.gz", timestamp);
        let backup_path = Path::new(&self.destination).join(&backup_name);

        // Create tar.gz archive
        std::process::Command::new("tar")
            .args(["-czf", backup_path.to_str().unwrap(), &self.source])
            .output()?;

        Ok(backup_path.to_string_lossy().to_string())
    }

    fn cleanup_old_backups(&self) -> Result<usize, std::io::Error> {
        let mut removed = 0;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(self.retention_days as i64);

        for entry in fs::read_dir(&self.destination)? {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if let Ok(modified) = metadata.modified() {
                let modified_time: chrono::DateTime<chrono::Utc> = modified.into();
                if modified_time < cutoff {
                    fs::remove_file(entry.path())?;
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }
}
```

### A03: Log Aggregator
Collect and analyze logs from multiple sources:

```rust
use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;

struct LogAggregator {
    sources: Vec<String>,
    patterns: Vec<(String, Regex)>,
}

impl LogAggregator {
    fn process(&self) -> Vec<LogEntry> {
        let mut entries = Vec::new();

        for source in &self.sources {
            if let Ok(file) = File::open(source) {
                let reader = BufReader::new(file);

                for line in reader.lines().flatten() {
                    for (name, pattern) in &self.patterns {
                        if pattern.is_match(&line) {
                            entries.push(LogEntry {
                                source: source.clone(),
                                pattern_name: name.clone(),
                                content: line.clone(),
                            });
                        }
                    }
                }
            }
        }

        entries
    }
}

struct LogEntry {
    source: String,
    pattern_name: String,
    content: String,
}
```

### A04: Health Monitor
System health checking with alerting:

```rust
use std::time::Duration;

struct HealthMonitor {
    checks: Vec<Box<dyn HealthCheck>>,
    alert_handler: Box<dyn AlertHandler>,
}

trait HealthCheck {
    fn name(&self) -> &str;
    fn check(&self) -> HealthResult;
}

trait AlertHandler {
    fn send_alert(&self, message: &str);
}

enum HealthResult {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

impl HealthMonitor {
    fn run_checks(&self) -> Vec<(&str, HealthResult)> {
        self.checks.iter()
            .map(|check| (check.name(), check.check()))
            .collect()
    }

    fn monitor_loop(&self, interval: Duration) {
        loop {
            let results = self.run_checks();

            for (name, result) in &results {
                match result {
                    HealthResult::Unhealthy(msg) => {
                        self.alert_handler.send_alert(
                            &format!("CRITICAL: {} - {}", name, msg)
                        );
                    }
                    HealthResult::Degraded(msg) => {
                        self.alert_handler.send_alert(
                            &format!("WARNING: {} - {}", name, msg)
                        );
                    }
                    HealthResult::Healthy => {}
                }
            }

            std::thread::sleep(interval);
        }
    }
}
```

## Crates for Automation

| Crate | Purpose |
|-------|---------|
| `clap` | CLI parsing |
| `tokio` | Async runtime |
| `cron` | Cron scheduling |
| `notify` | File system watching |
| `reqwest` | HTTP client |
| `lettre` | Email sending |
| `serde` | Configuration |

## Best Practices

1. **Idempotency**: Operations should be safe to run multiple times
2. **Logging**: Comprehensive logging for debugging
3. **Error Handling**: Graceful failure and recovery
4. **Configuration**: External config files, not hardcoded values
5. **Testing**: Test automation scripts thoroughly
6. **Documentation**: Document what each script does

## Usage Example

```bash
# Run backup with rotation
./backup_manager --source /data --dest /backups --retain 30

# Monitor services
./health_monitor --config health.toml --interval 60

# Process logs
./log_aggregator --sources /var/log/*.log --pattern "error|warning"
```
