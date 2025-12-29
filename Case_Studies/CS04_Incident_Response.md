# Case Study 04: Incident Response Toolkit

## Scenario

You're part of a security incident response team. A suspected breach has occurred on a Linux server. Build a toolkit to collect forensic artifacts, analyze system state, and generate a comprehensive report.

---

## Learning Objectives

- Collect system artifacts for forensic analysis
- Parse and correlate log files
- Generate timeline of events
- Create professional incident reports
- Handle evidence with integrity

---

## Phase 1: Artifact Collection

### System Information Collector

```rust
use std::process::Command;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use chrono::{Local, DateTime, Utc};
use sha2::{Sha256, Digest};

#[derive(Debug)]
struct SystemInfo {
    hostname: String,
    os_release: String,
    kernel_version: String,
    uptime: String,
    current_time: DateTime<Utc>,
    timezone: String,
}

#[derive(Debug)]
struct ArtifactCollector {
    output_dir: PathBuf,
    collection_time: DateTime<Utc>,
    artifacts: Vec<CollectedArtifact>,
}

#[derive(Debug)]
struct CollectedArtifact {
    name: String,
    path: PathBuf,
    hash: String,
    size: u64,
}

impl ArtifactCollector {
    fn new(output_dir: &str) -> Self {
        let dir = PathBuf::from(output_dir);
        fs::create_dir_all(&dir).expect("Cannot create output directory");

        Self {
            output_dir: dir,
            collection_time: Utc::now(),
            artifacts: Vec::new(),
        }
    }

    fn run_command(&self, cmd: &str, args: &[&str]) -> String {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|e| format!("Error: {}", e))
    }

    fn collect_system_info(&mut self) -> SystemInfo {
        SystemInfo {
            hostname: self.run_command("hostname", &[]).trim().to_string(),
            os_release: fs::read_to_string("/etc/os-release")
                .unwrap_or_else(|_| "Unknown".to_string()),
            kernel_version: self.run_command("uname", &["-r"]).trim().to_string(),
            uptime: self.run_command("uptime", &[]).trim().to_string(),
            current_time: Utc::now(),
            timezone: self.run_command("date", &["+%Z"]).trim().to_string(),
        }
    }

    fn collect_file(&mut self, source: &str, name: &str) -> Result<(), String> {
        let source_path = PathBuf::from(source);

        if !source_path.exists() {
            return Err(format!("File not found: {}", source));
        }

        let dest_path = self.output_dir.join(name);

        // Read and hash the file
        let content = fs::read(&source_path)
            .map_err(|e| format!("Cannot read {}: {}", source, e))?;

        let hash = format!("{:x}", Sha256::digest(&content));
        let size = content.len() as u64;

        // Write to output directory
        fs::write(&dest_path, &content)
            .map_err(|e| format!("Cannot write {}: {}", name, e))?;

        self.artifacts.push(CollectedArtifact {
            name: name.to_string(),
            path: dest_path,
            hash,
            size,
        });

        Ok(())
    }

    fn collect_command_output(&mut self, cmd: &str, args: &[&str], name: &str) -> Result<(), String> {
        let output = self.run_command(cmd, args);
        let dest_path = self.output_dir.join(name);

        let hash = format!("{:x}", Sha256::digest(output.as_bytes()));
        let size = output.len() as u64;

        fs::write(&dest_path, &output)
            .map_err(|e| format!("Cannot write {}: {}", name, e))?;

        self.artifacts.push(CollectedArtifact {
            name: name.to_string(),
            path: dest_path,
            hash,
            size,
        });

        Ok(())
    }

    fn generate_manifest(&self) -> String {
        let mut manifest = String::new();

        manifest.push_str("# Forensic Collection Manifest\n");
        manifest.push_str(&format!("Collection Time: {}\n", self.collection_time));
        manifest.push_str(&format!("Output Directory: {}\n\n", self.output_dir.display()));
        manifest.push_str("## Artifacts\n\n");
        manifest.push_str("| File | Size | SHA256 |\n");
        manifest.push_str("|------|------|--------|\n");

        for artifact in &self.artifacts {
            manifest.push_str(&format!(
                "| {} | {} | {} |\n",
                artifact.name, artifact.size, artifact.hash
            ));
        }

        manifest
    }
}

fn main() {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let output_dir = format!("/tmp/ir_collection_{}", timestamp);

    let mut collector = ArtifactCollector::new(&output_dir);

    println!("=== Incident Response Artifact Collection ===\n");
    println!("Output directory: {}\n", output_dir);

    // Collect system info
    let sys_info = collector.collect_system_info();
    println!("Hostname: {}", sys_info.hostname);
    println!("Kernel: {}", sys_info.kernel_version);

    // Collect files
    let files_to_collect = vec![
        ("/etc/passwd", "passwd.txt"),
        ("/etc/shadow", "shadow.txt"),
        ("/etc/group", "group.txt"),
        ("/var/log/auth.log", "auth.log"),
        ("/var/log/syslog", "syslog"),
        ("/etc/crontab", "crontab.txt"),
        ("/root/.bash_history", "root_bash_history.txt"),
    ];

    println!("\nCollecting files:");
    for (source, name) in files_to_collect {
        match collector.collect_file(source, name) {
            Ok(_) => println!("  [+] {}", source),
            Err(e) => println!("  [-] {} - {}", source, e),
        }
    }

    // Collect command outputs
    let commands = vec![
        ("ps", vec!["auxf"], "processes.txt"),
        ("netstat", vec!["-tulpn"], "network_connections.txt"),
        ("ss", vec!["-tulpn"], "sockets.txt"),
        ("who", vec![], "logged_in_users.txt"),
        ("last", vec!["-100"], "login_history.txt"),
        ("crontab", vec!["-l"], "user_crontab.txt"),
        ("find", vec!["/tmp", "-type", "f", "-mtime", "-7"], "recent_tmp_files.txt"),
        ("lsof", vec!["-i"], "open_network_files.txt"),
    ];

    println!("\nCollecting command outputs:");
    for (cmd, args, name) in commands {
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match collector.collect_command_output(cmd, &args_ref, name) {
            Ok(_) => println!("  [+] {} -> {}", cmd, name),
            Err(e) => println!("  [-] {} - {}", cmd, e),
        }
    }

    // Generate and save manifest
    let manifest = collector.generate_manifest();
    let manifest_path = format!("{}/MANIFEST.md", output_dir);
    fs::write(&manifest_path, &manifest).expect("Cannot write manifest");

    println!("\n=== Collection Complete ===");
    println!("Artifacts: {}", collector.artifacts.len());
    println!("Manifest: {}", manifest_path);
}
```

---

## Phase 2: Log Timeline Generator

```rust
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::BTreeMap;
use regex::Regex;
use chrono::{NaiveDateTime, Duration};

#[derive(Debug, Clone)]
struct TimelineEvent {
    timestamp: NaiveDateTime,
    source: String,
    event_type: String,
    details: String,
    severity: Severity,
}

#[derive(Debug, Clone, Copy)]
enum Severity {
    Info,
    Warning,
    Alert,
    Critical,
}

struct TimelineBuilder {
    events: Vec<TimelineEvent>,
    patterns: Vec<(Regex, Severity, String)>,
}

impl TimelineBuilder {
    fn new() -> Self {
        let patterns = vec![
            (Regex::new(r"(?i)failed.*password").unwrap(), Severity::Warning, "AUTH_FAILURE".to_string()),
            (Regex::new(r"(?i)accepted.*password").unwrap(), Severity::Info, "AUTH_SUCCESS".to_string()),
            (Regex::new(r"(?i)sudo:").unwrap(), Severity::Alert, "SUDO_USAGE".to_string()),
            (Regex::new(r"(?i)session opened").unwrap(), Severity::Info, "SESSION_START".to_string()),
            (Regex::new(r"(?i)session closed").unwrap(), Severity::Info, "SESSION_END".to_string()),
            (Regex::new(r"(?i)invalid user").unwrap(), Severity::Warning, "INVALID_USER".to_string()),
            (Regex::new(r"(?i)connection from").unwrap(), Severity::Info, "CONNECTION".to_string()),
            (Regex::new(r"(?i)(error|critical|emergency)").unwrap(), Severity::Alert, "ERROR".to_string()),
        ];

        Self {
            events: Vec::new(),
            patterns,
        }
    }

    fn parse_syslog_timestamp(&self, line: &str) -> Option<NaiveDateTime> {
        // Format: "Jan 15 10:30:45"
        let re = Regex::new(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})").ok()?;
        let caps = re.captures(line)?;

        let month_str = caps.get(1)?.as_str();
        let day: u32 = caps.get(2)?.as_str().parse().ok()?;
        let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
        let min: u32 = caps.get(4)?.as_str().parse().ok()?;
        let sec: u32 = caps.get(5)?.as_str().parse().ok()?;

        let month = match month_str {
            "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
            "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
            "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
            _ => return None,
        };

        NaiveDateTime::parse_from_str(
            &format!("2024-{:02}-{:02} {:02}:{:02}:{:02}", month, day, hour, min, sec),
            "%Y-%m-%d %H:%M:%S"
        ).ok()
    }

    fn add_log_file(&mut self, path: &str, source: &str) {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return,
        };

        let reader = BufReader::new(file);

        for line in reader.lines().filter_map(|l| l.ok()) {
            if let Some(timestamp) = self.parse_syslog_timestamp(&line) {
                // Check against patterns
                for (pattern, severity, event_type) in &self.patterns {
                    if pattern.is_match(&line) {
                        self.events.push(TimelineEvent {
                            timestamp,
                            source: source.to_string(),
                            event_type: event_type.clone(),
                            details: line.clone(),
                            severity: *severity,
                        });
                        break;
                    }
                }
            }
        }
    }

    fn sort_by_time(&mut self) {
        self.events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    fn filter_time_range(&self, start: NaiveDateTime, end: NaiveDateTime) -> Vec<&TimelineEvent> {
        self.events.iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# Incident Timeline Report\n\n");
        report.push_str(&format!("Total events: {}\n\n", self.events.len()));

        report.push_str("## Event Summary\n\n");

        // Count by type
        let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
        for event in &self.events {
            *by_type.entry(&event.event_type).or_insert(0) += 1;
        }

        for (event_type, count) in by_type {
            report.push_str(&format!("- {}: {}\n", event_type, count));
        }

        report.push_str("\n## Timeline\n\n");
        report.push_str("| Time | Source | Type | Severity | Details |\n");
        report.push_str("|------|--------|------|----------|--------|\n");

        for event in &self.events {
            let severity_str = match event.severity {
                Severity::Info => "INFO",
                Severity::Warning => "WARN",
                Severity::Alert => "ALERT",
                Severity::Critical => "CRIT",
            };

            let details = if event.details.len() > 50 {
                format!("{}...", &event.details[..47])
            } else {
                event.details.clone()
            };

            report.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                event.timestamp.format("%H:%M:%S"),
                event.source,
                event.event_type,
                severity_str,
                details
            ));
        }

        report
    }
}

fn main() {
    let mut timeline = TimelineBuilder::new();

    println!("Building incident timeline...\n");

    // Add log files
    timeline.add_log_file("/var/log/auth.log", "auth.log");
    timeline.add_log_file("/var/log/syslog", "syslog");

    timeline.sort_by_time();

    println!("Events found: {}", timeline.events.len());

    let report = timeline.generate_report();
    println!("\n{}", report);
}
```

---

## Phase 3: IOC Matcher

```rust
use std::collections::HashSet;
use std::fs;
use sha2::{Sha256, Digest};
use walkdir::WalkDir;

struct IOCDatabase {
    malicious_hashes: HashSet<String>,
    malicious_ips: HashSet<String>,
    malicious_domains: HashSet<String>,
    suspicious_paths: Vec<String>,
}

#[derive(Debug)]
struct IOCMatch {
    ioc_type: String,
    value: String,
    location: String,
    context: String,
}

impl IOCDatabase {
    fn new() -> Self {
        Self {
            malicious_hashes: HashSet::new(),
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
            suspicious_paths: vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/dev/shm".to_string(),
            ],
        }
    }

    fn load_hash_iocs(&mut self, hashes: &[&str]) {
        for hash in hashes {
            self.malicious_hashes.insert(hash.to_lowercase());
        }
    }

    fn load_ip_iocs(&mut self, ips: &[&str]) {
        for ip in ips {
            self.malicious_ips.insert(ip.to_string());
        }
    }

    fn scan_file(&self, path: &str) -> Vec<IOCMatch> {
        let mut matches = Vec::new();

        // Check file hash
        if let Ok(content) = fs::read(path) {
            let hash = format!("{:x}", Sha256::digest(&content));

            if self.malicious_hashes.contains(&hash) {
                matches.push(IOCMatch {
                    ioc_type: "HASH".to_string(),
                    value: hash,
                    location: path.to_string(),
                    context: "File hash matches known malware".to_string(),
                });
            }

            // Check content for IPs
            let content_str = String::from_utf8_lossy(&content);
            for ip in &self.malicious_ips {
                if content_str.contains(ip) {
                    matches.push(IOCMatch {
                        ioc_type: "IP".to_string(),
                        value: ip.clone(),
                        location: path.to_string(),
                        context: "Malicious IP found in file content".to_string(),
                    });
                }
            }
        }

        matches
    }

    fn scan_directory(&self, dir: &str) -> Vec<IOCMatch> {
        let mut all_matches = Vec::new();

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let matches = self.scan_file(entry.path().to_str().unwrap_or(""));
            all_matches.extend(matches);
        }

        all_matches
    }
}

fn main() {
    let mut ioc_db = IOCDatabase::new();

    // Load sample IOCs
    ioc_db.load_hash_iocs(&[
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  // empty file
    ]);

    ioc_db.load_ip_iocs(&[
        "198.51.100.1",
        "203.0.113.50",
    ]);

    println!("=== IOC Scanner ===\n");
    println!("Scanning /tmp for indicators of compromise...\n");

    let matches = ioc_db.scan_directory("/tmp");

    if matches.is_empty() {
        println!("No IOC matches found.");
    } else {
        println!("Found {} IOC matches:\n", matches.len());
        for m in matches {
            println!("[{}] {}", m.ioc_type, m.value);
            println!("  Location: {}", m.location);
            println!("  Context: {}\n", m.context);
        }
    }
}
```

---

## Complete Incident Response Tool

```rust
// See full implementation in Projects/IncidentResponse/
// Combines all phases into a single executable toolkit
```

---

## Key Takeaways

1. **Evidence integrity** - Hash everything you collect
2. **Chain of custody** - Document all actions
3. **Timeline is critical** - Correlate events across sources
4. **Automate collection** - Manual is error-prone
5. **Report professionally** - Clear, factual, defensible

---

## Exercises

1. Extend the collector to support Windows artifacts
2. Add network traffic capture capability
3. Implement memory dump analysis
4. Create a web-based report viewer

---

[← Back to Case Studies](./README.md) | [Next: CS05 →](./CS05_Malware_Analysis.md)
