# Blue Team: Detection Engineering

## Overview

Detection tools to identify threats, analyze logs, and hunt for adversaries.

## Projects

| ID | Name | Description |
|----|------|-------------|
| BT01 | IOC Scanner | Scan for known malicious indicators |
| BT02 | Log Analyzer | Parse and analyze security logs |
| BT03 | Process Hunter | Find suspicious processes |
| BT04 | Network Monitor | Detect anomalous network activity |
| BT05 | YARA Scanner | Run YARA rules against files |

## BT01: IOC Scanner

Comprehensive Indicator of Compromise scanner:

```rust
//! IOC Scanner - Detect known malicious indicators
//!
//! Supports:
//! - File hashes (MD5, SHA1, SHA256)
//! - IP addresses
//! - Domain names
//! - File paths
//! - Registry keys (Windows)

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use sha2::{Sha256, Digest};
use walkdir::WalkDir;

#[derive(Default)]
struct IOCDatabase {
    hashes: HashSet<String>,
    ips: HashSet<String>,
    domains: HashSet<String>,
    paths: HashSet<String>,
}

impl IOCDatabase {
    fn load(&mut self, path: &str) -> Result<usize, std::io::Error> {
        let content = fs::read_to_string(path)?;
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim().to_lowercase();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Detect IOC type
            if line.len() == 32 || line.len() == 40 || line.len() == 64 {
                self.hashes.insert(line);
            } else if line.parse::<std::net::IpAddr>().is_ok() {
                self.ips.insert(line);
            } else if line.contains('.') && !line.contains('/') {
                self.domains.insert(line);
            } else {
                self.paths.insert(line);
            }
            count += 1;
        }

        Ok(count)
    }
}

struct IOCScanner {
    db: IOCDatabase,
}

impl IOCScanner {
    fn scan_directory(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                if let Some(finding) = self.scan_file(entry.path()) {
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn scan_file(&self, path: &Path) -> Option<Finding> {
        let data = fs::read(path).ok()?;
        let hash = format!("{:x}", Sha256::digest(&data));

        if self.db.hashes.contains(&hash) {
            return Some(Finding {
                path: path.to_path_buf(),
                ioc_type: IOCType::Hash,
                value: hash,
                severity: Severity::Critical,
            });
        }

        None
    }
}

struct Finding {
    path: std::path::PathBuf,
    ioc_type: IOCType,
    value: String,
    severity: Severity,
}

enum IOCType {
    Hash,
    IP,
    Domain,
    Path,
}

enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
```

## BT02: Log Analyzer

Parse and analyze Windows/Linux security logs:

```rust
//! Log Analyzer - Security event parsing
//!
//! Supports:
//! - Windows Event Logs (XML, EVTX)
//! - Linux auth.log, syslog
//! - Apache/Nginx access logs
//! - Custom formats

use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};

struct LogAnalyzer {
    patterns: Vec<DetectionPattern>,
}

struct DetectionPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
}

impl LogAnalyzer {
    fn new() -> Self {
        let mut analyzer = Self { patterns: Vec::new() };

        // Add default detection patterns
        analyzer.add_pattern(DetectionPattern {
            name: "Failed SSH Login".to_string(),
            regex: Regex::new(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)").unwrap(),
            severity: Severity::Medium,
            description: "SSH brute force attempt".to_string(),
        });

        analyzer.add_pattern(DetectionPattern {
            name: "Sudo Abuse".to_string(),
            regex: Regex::new(r"sudo:.+NOT in sudoers").unwrap(),
            severity: Severity::High,
            description: "Privilege escalation attempt".to_string(),
        });

        analyzer
    }

    fn add_pattern(&mut self, pattern: DetectionPattern) {
        self.patterns.push(pattern);
    }

    fn analyze_file(&self, path: &str) -> Vec<LogAlert> {
        let mut alerts = Vec::new();

        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);

            for (line_num, line) in reader.lines().enumerate() {
                if let Ok(line) = line {
                    for pattern in &self.patterns {
                        if pattern.regex.is_match(&line) {
                            alerts.push(LogAlert {
                                pattern_name: pattern.name.clone(),
                                line_number: line_num + 1,
                                content: line.clone(),
                                severity: pattern.severity.clone(),
                            });
                        }
                    }
                }
            }
        }

        alerts
    }
}

struct LogAlert {
    pattern_name: String,
    line_number: usize,
    content: String,
    severity: Severity,
}
```

## BT03: Process Hunter

Find suspicious processes and behaviors:

```rust
//! Process Hunter - Detect suspicious process activity
//!
//! Detects:
//! - Suspicious command lines
//! - Unusual parent-child relationships
//! - Hidden processes
//! - Processes with suspicious network activity

struct ProcessHunter {
    suspicious_cmds: Vec<String>,
    suspicious_parents: Vec<(String, String)>, // (parent, child) pairs
}

impl ProcessHunter {
    fn new() -> Self {
        Self {
            suspicious_cmds: vec![
                "powershell.*-enc".to_string(),
                "cmd.*/c.*curl".to_string(),
                "certutil.*-urlcache".to_string(),
                "bitsadmin.*/transfer".to_string(),
                "mshta.*http".to_string(),
                "regsvr32.*/s.*/n.*/u".to_string(),
                "rundll32.*javascript".to_string(),
            ],
            suspicious_parents: vec![
                ("excel.exe".to_string(), "cmd.exe".to_string()),
                ("word.exe".to_string(), "powershell.exe".to_string()),
                ("outlook.exe".to_string(), "cmd.exe".to_string()),
            ],
        }
    }

    fn hunt(&self) -> Vec<ProcessAlert> {
        // Implementation would enumerate processes
        // and check against suspicious patterns
        Vec::new()
    }
}
```

## Usage

```bash
# Scan directory for IOCs
./ioc_scanner -d /home/user -i iocs.txt

# Analyze auth logs
./log_analyzer -f /var/log/auth.log --pattern failed_ssh

# Hunt for suspicious processes
./process_hunter --all-users --output json
```

## Integration

These tools can integrate with:
- SIEM platforms (Splunk, Elastic)
- EDR solutions
- Ticketing systems
- Alerting platforms (PagerDuty, Slack)
