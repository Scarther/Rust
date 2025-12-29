# Chapter 10: Real World Scenarios

## Overview

Practice Rust security programming through realistic scenarios based on actual security tasks and tools commonly used in the field.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     REAL WORLD SCENARIO PROGRESSION                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   BASIC                     INTERMEDIATE              ADVANCED               │
│   ─────                     ────────────              ────────               │
│   • Log parser              • Service monitor         • Memory scanner       │
│   • Hash verifier           • Credential checker      • Traffic analyzer     │
│   • Config auditor          • API security tester     • Threat hunter        │
│                                                                              │
│                                     │                                        │
│                                     ▼                                        │
│                               ┌─────────────┐                               │
│                               │   EXPERT    │                               │
│                               │  ─────────  │                               │
│                               │ • EDR agent │                               │
│                               │ • Sandbox   │                               │
│                               │ • C2 detect │                               │
│                               └─────────────┘                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Sections

| Section | Level | Focus | Real-World Equivalent |
|---------|-------|-------|----------------------|
| [01_Basic](01_Basic/) | Beginner | Log analysis, file ops | SOC Analyst daily tasks |
| [02_Intermediate](02_Intermediate/) | Intermediate | Monitoring, testing | Security Engineer tools |
| [03_Advanced](03_Advanced/) | Advanced | Detection, analysis | Threat Hunter workflows |
| [04_Expert](04_Expert/) | Expert | Prevention, response | Security Researcher tools |

## Learning Objectives

By the end of this chapter, you will be able to:
1. Build tools used daily in security operations
2. Understand common security tool architectures
3. Apply Rust patterns to real-world problems
4. Create production-quality security software
5. Bridge the gap between learning and applying

## Prerequisites

- Completed Chapters 1-9
- Basic understanding of security operations
- Familiarity with common security tools

---

## Scenario Overview by Level

### Basic Level (SOC Analyst)

Tasks that a junior SOC analyst might perform daily:

| Scenario | Description | Skills Practiced |
|----------|-------------|------------------|
| RW-B01 | Log Parser | File I/O, regex, timestamps |
| RW-B02 | IOC Checker | File hashing, list matching |
| RW-B03 | Config Auditor | TOML/JSON parsing, validation |
| RW-B04 | Password Policy Checker | String analysis, rules |
| RW-B05 | User Activity Monitor | Process listing, timestamps |

### Intermediate Level (Security Engineer)

Tools that security engineers build or use:

| Scenario | Description | Skills Practiced |
|----------|-------------|------------------|
| RW-I01 | Service Health Monitor | HTTP checks, async, alerting |
| RW-I02 | Credential Leak Checker | API integration, hashing |
| RW-I03 | SSL Certificate Scanner | TLS, certificate parsing |
| RW-I04 | API Security Tester | HTTP client, fuzzing basics |
| RW-I05 | Backup Integrity Checker | Checksums, scheduling |

### Advanced Level (Threat Hunter)

Specialized tools for threat detection:

| Scenario | Description | Skills Practiced |
|----------|-------------|------------------|
| RW-A01 | Process Hollowing Detector | Memory analysis, PE parsing |
| RW-A02 | DNS Tunnel Detector | Traffic analysis, entropy |
| RW-A03 | Persistence Hunter | Registry, scheduled tasks |
| RW-A04 | Lateral Movement Detector | Network analysis, patterns |
| RW-A05 | Exfil Detection | Traffic baselining, anomalies |

### Expert Level (Security Researcher)

Complex security tools and frameworks:

| Scenario | Description | Skills Practiced |
|----------|-------------|------------------|
| RW-E01 | Mini EDR Agent | Hooks, events, response |
| RW-E02 | Malware Sandbox | Process isolation, monitoring |
| RW-E03 | C2 Beacon Detector | Protocol analysis, ML basics |
| RW-E04 | Vulnerability Scanner | Network, protocol fuzzing |
| RW-E05 | Incident Response Toolkit | Forensics, automation |

---

## Quick Start: Basic Log Parser

Here's a preview - a simple but practical log parser:

```rust
//! RW-B01: Security Log Parser
//!
//! Parses common log formats and extracts security-relevant events.
//! Similar to what a SOC analyst would use for initial triage.

use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use chrono::{DateTime, Utc, NaiveDateTime};
use serde::{Serialize, Deserialize};

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// A parsed log entry
///
/// # Real-World Context
/// SOC analysts deal with thousands of log entries daily.
/// Having a standardized structure makes correlation easier.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    /// When the event occurred
    timestamp: String,

    /// Source of the log (auth, syslog, apache, etc.)
    source: String,

    /// Severity level
    level: LogLevel,

    /// The actual message
    message: String,

    /// Extracted indicators (IPs, users, etc.)
    indicators: Vec<Indicator>,
}

/// Log severity levels
///
/// # Standard Syslog Levels
/// Maps to syslog severity for consistency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq)]
enum LogLevel {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    Alert = 6,
    Emergency = 7,
}

/// Extracted indicator from log
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Indicator {
    /// Type of indicator
    indicator_type: IndicatorType,
    /// The value
    value: String,
}

/// Types of indicators we extract
#[derive(Debug, Clone, Serialize, Deserialize)]
enum IndicatorType {
    IpAddress,
    Username,
    Hostname,
    FilePath,
    Port,
}

/// Security event detected in logs
#[derive(Debug, Clone)]
struct SecurityEvent {
    /// Event type
    event_type: EventType,
    /// Timestamp
    timestamp: String,
    /// Description
    description: String,
    /// Related log entries
    related_logs: Vec<LogEntry>,
    /// Risk score (1-10)
    risk_score: u8,
}

/// Types of security events we detect
#[derive(Debug, Clone)]
enum EventType {
    FailedLogin,
    SuccessfulLogin,
    PrivilegeEscalation,
    SuspiciousCommand,
    ServiceStart,
    ServiceStop,
    FileAccess,
    NetworkConnection,
}

// ═══════════════════════════════════════════════════════════════════════════
// LOG PARSER
// ═══════════════════════════════════════════════════════════════════════════

/// Parser for various log formats
///
/// # Supported Formats
/// - Syslog (RFC 3164 and RFC 5424)
/// - Apache/Nginx access logs
/// - SSH auth logs
/// - Windows Event Log (exported)
struct LogParser {
    /// Pattern for auth.log failed logins
    failed_login_pattern: Regex,

    /// Pattern for successful logins
    success_login_pattern: Regex,

    /// Pattern for IP addresses
    ip_pattern: Regex,

    /// Pattern for usernames
    user_pattern: Regex,

    /// Pattern for suspicious commands
    suspicious_commands: Vec<String>,
}

impl LogParser {
    fn new() -> Self {
        LogParser {
            failed_login_pattern: Regex::new(
                r"(?i)(failed|invalid|error).*(password|login|auth)"
            ).unwrap(),

            success_login_pattern: Regex::new(
                r"(?i)(accepted|successful).*(password|login|auth)"
            ).unwrap(),

            ip_pattern: Regex::new(
                r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
            ).unwrap(),

            user_pattern: Regex::new(
                r"(?:user[= ]|for )([a-zA-Z0-9_-]+)"
            ).unwrap(),

            suspicious_commands: vec![
                "wget".to_string(),
                "curl".to_string(),
                "nc ".to_string(),
                "ncat".to_string(),
                "/bin/sh".to_string(),
                "/bin/bash".to_string(),
                "chmod 777".to_string(),
                "chmod +x".to_string(),
                "base64".to_string(),
                "python -c".to_string(),
                "perl -e".to_string(),
            ],
        }
    }

    /// Parses a log file and returns entries
    fn parse_file(&self, path: &str) -> Result<Vec<LogEntry>, String> {
        let file = File::open(path)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("Read error at line {}: {}", line_num, e))?;

            if let Some(entry) = self.parse_line(&line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Parses a single log line
    fn parse_line(&self, line: &str) -> Option<LogEntry> {
        // Skip empty lines
        if line.trim().is_empty() {
            return None;
        }

        // Extract timestamp (assumes syslog format)
        let timestamp = self.extract_timestamp(line);

        // Determine log level
        let level = self.determine_level(line);

        // Extract indicators
        let indicators = self.extract_indicators(line);

        Some(LogEntry {
            timestamp,
            source: "syslog".to_string(),
            level,
            message: line.to_string(),
            indicators,
        })
    }

    /// Extracts timestamp from log line
    fn extract_timestamp(&self, line: &str) -> String {
        // Syslog format: "Mon DD HH:MM:SS"
        if line.len() >= 15 {
            let month = &line[0..3];
            if ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].contains(&month) {
                return line[0..15].to_string();
            }
        }

        // ISO format: "2024-01-15T10:30:00"
        if let Some(idx) = line.find('T') {
            if idx >= 10 && line.len() >= idx + 9 {
                return line[idx-10..idx+9].to_string();
            }
        }

        "unknown".to_string()
    }

    /// Determines log level from content
    fn determine_level(&self, line: &str) -> LogLevel {
        let lower = line.to_lowercase();

        if lower.contains("emergency") || lower.contains("emerg") {
            LogLevel::Emergency
        } else if lower.contains("alert") {
            LogLevel::Alert
        } else if lower.contains("critical") || lower.contains("crit") {
            LogLevel::Critical
        } else if lower.contains("error") || lower.contains("err") {
            LogLevel::Error
        } else if lower.contains("warning") || lower.contains("warn") {
            LogLevel::Warning
        } else if lower.contains("notice") {
            LogLevel::Notice
        } else if lower.contains("debug") {
            LogLevel::Debug
        } else {
            LogLevel::Info
        }
    }

    /// Extracts indicators from log line
    fn extract_indicators(&self, line: &str) -> Vec<Indicator> {
        let mut indicators = Vec::new();

        // Extract IP addresses
        for cap in self.ip_pattern.captures_iter(line) {
            indicators.push(Indicator {
                indicator_type: IndicatorType::IpAddress,
                value: cap[1].to_string(),
            });
        }

        // Extract usernames
        for cap in self.user_pattern.captures_iter(line) {
            indicators.push(Indicator {
                indicator_type: IndicatorType::Username,
                value: cap[1].to_string(),
            });
        }

        indicators
    }

    /// Detects security events from log entries
    fn detect_events(&self, entries: &[LogEntry]) -> Vec<SecurityEvent> {
        let mut events = Vec::new();

        for entry in entries {
            // Check for failed logins
            if self.failed_login_pattern.is_match(&entry.message) {
                events.push(SecurityEvent {
                    event_type: EventType::FailedLogin,
                    timestamp: entry.timestamp.clone(),
                    description: "Failed login attempt detected".to_string(),
                    related_logs: vec![entry.clone()],
                    risk_score: 3,
                });
            }

            // Check for successful logins
            if self.success_login_pattern.is_match(&entry.message) {
                events.push(SecurityEvent {
                    event_type: EventType::SuccessfulLogin,
                    timestamp: entry.timestamp.clone(),
                    description: "Successful login".to_string(),
                    related_logs: vec![entry.clone()],
                    risk_score: 1,
                });
            }

            // Check for suspicious commands
            for cmd in &self.suspicious_commands {
                if entry.message.contains(cmd) {
                    events.push(SecurityEvent {
                        event_type: EventType::SuspiciousCommand,
                        timestamp: entry.timestamp.clone(),
                        description: format!("Suspicious command detected: {}", cmd),
                        related_logs: vec![entry.clone()],
                        risk_score: 7,
                    });
                }
            }
        }

        events
    }

    /// Correlates events to detect patterns
    fn correlate_events(&self, events: &[SecurityEvent]) -> Vec<String> {
        let mut findings = Vec::new();

        // Count failed logins by source IP
        let mut failed_by_ip: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for event in events {
            if let EventType::FailedLogin = event.event_type {
                for log in &event.related_logs {
                    for indicator in &log.indicators {
                        if let IndicatorType::IpAddress = indicator.indicator_type {
                            *failed_by_ip.entry(indicator.value.clone()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        // Flag brute force attempts (>5 failures from same IP)
        for (ip, count) in &failed_by_ip {
            if *count > 5 {
                findings.push(format!(
                    "ALERT: Possible brute force from {} ({} failed attempts)",
                    ip, count
                ));
            }
        }

        findings
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║              SECURITY LOG PARSER                                ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    let parser = LogParser::new();

    // Example: Parse auth.log
    let log_path = "/var/log/auth.log";

    match parser.parse_file(log_path) {
        Ok(entries) => {
            println!("[*] Parsed {} log entries", entries.len());

            // Detect events
            let events = parser.detect_events(&entries);
            println!("[*] Detected {} security events", events.len());

            // Show high-risk events
            let high_risk: Vec<_> = events.iter()
                .filter(|e| e.risk_score >= 5)
                .collect();

            if !high_risk.is_empty() {
                println!("\n[!] High-Risk Events:");
                for event in high_risk {
                    println!("    [{:?}] {} (risk: {})",
                        event.event_type,
                        event.description,
                        event.risk_score
                    );
                }
            }

            // Correlate
            let findings = parser.correlate_events(&events);
            if !findings.is_empty() {
                println!("\n[!] Correlated Findings:");
                for finding in findings {
                    println!("    {}", finding);
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Error: {}", e);
            println!("\n[*] Using sample data for demonstration...");
            // Demo with sample logs would go here
        }
    }
}
```

---

## How to Use This Chapter

### For Self-Study
1. Start with Basic scenarios
2. Implement each tool from scratch
3. Compare with the provided solutions
4. Add your own features

### For Team Training
1. Use scenarios as coding challenges
2. Time-box implementations
3. Review and compare approaches
4. Discuss trade-offs

### For Building a Portfolio
1. Complete all scenarios
2. Add documentation
3. Create a GitHub repo
4. Write blog posts about your solutions

---

Continue to the specific level sections for detailed implementations.

[→ 01_Basic](01_Basic/) | [→ 02_Intermediate](02_Intermediate/) | [→ 03_Advanced](03_Advanced/) | [→ 04_Expert](04_Expert/)
