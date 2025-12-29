# Chapter 4: Blue Team Rust

## Overview

Defensive security tools for detection, monitoring, forensics, and incident response.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BLUE TEAM DEFENSE LAYERS                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                          ┌─────────────────┐                                │
│                          │    DETECTION    │                                │
│                          │  SIEM, EDR, IDS │                                │
│                          └────────┬────────┘                                │
│                                   │                                          │
│               ┌───────────────────┼───────────────────┐                     │
│               ▼                   ▼                   ▼                     │
│    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐           │
│    │   PREVENTION    │  │   MONITORING    │  │    RESPONSE     │           │
│    │   Hardening     │  │   Logging       │  │   Forensics     │           │
│    │   Patching      │  │   Alerting      │  │   Containment   │           │
│    └─────────────────┘  └─────────────────┘  └─────────────────┘           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Sections

| Section | Focus | Projects |
|---------|-------|----------|
| [01_Detection](01_Detection/) | Threat identification | IOC scanner, YARA engine, log analyzer |
| [02_Forensics](02_Forensics/) | Evidence analysis | Memory analysis, disk forensics, timeline |
| [03_Hardening](03_Hardening/) | System protection | Config auditor, baseline checker |
| [04_Incident_Response](04_Incident_Response/) | Active response | Artifact collector, triage tools |

## Key Projects

### File Integrity Monitor
Detect unauthorized file changes:

```rust
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

struct IntegrityMonitor {
    baseline: HashMap<String, String>,
}

impl IntegrityMonitor {
    fn hash_file(path: &Path) -> Option<String> {
        let data = fs::read(path).ok()?;
        let hash = Sha256::digest(&data);
        Some(format!("{:x}", hash))
    }

    fn check(&self) -> Vec<IntegrityAlert> {
        let mut alerts = Vec::new();

        for (path, expected_hash) in &self.baseline {
            let path = Path::new(path);

            if !path.exists() {
                alerts.push(IntegrityAlert::Deleted(path.to_path_buf()));
                continue;
            }

            if let Some(current_hash) = Self::hash_file(path) {
                if &current_hash != expected_hash {
                    alerts.push(IntegrityAlert::Modified(path.to_path_buf()));
                }
            }
        }

        alerts
    }
}

enum IntegrityAlert {
    Modified(std::path::PathBuf),
    Deleted(std::path::PathBuf),
    Created(std::path::PathBuf),
}
```

### Process Monitor
Detect suspicious processes:

```rust
struct ProcessMonitor {
    suspicious_patterns: Vec<String>,
}

impl ProcessMonitor {
    fn scan(&self) -> Vec<ProcessAlert> {
        let mut alerts = Vec::new();

        // Check for suspicious command lines
        for proc in self.get_processes() {
            for pattern in &self.suspicious_patterns {
                if proc.cmdline.contains(pattern) {
                    alerts.push(ProcessAlert {
                        pid: proc.pid,
                        name: proc.name.clone(),
                        cmdline: proc.cmdline.clone(),
                        reason: format!("Matches pattern: {}", pattern),
                    });
                }
            }
        }

        alerts
    }

    fn get_processes(&self) -> Vec<ProcessInfo> {
        // Platform-specific process enumeration
        Vec::new()
    }
}

struct ProcessAlert {
    pid: u32,
    name: String,
    cmdline: String,
    reason: String,
}
```

### IOC Scanner
Scan for Indicators of Compromise:

```rust
use std::collections::HashSet;

struct IOCScanner {
    malicious_hashes: HashSet<String>,
    malicious_ips: HashSet<String>,
    malicious_domains: HashSet<String>,
}

impl IOCScanner {
    fn load_from_file(&mut self, path: &str) -> Result<(), std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.len() == 64 {
                self.malicious_hashes.insert(line.to_string());
            } else if line.parse::<std::net::IpAddr>().is_ok() {
                self.malicious_ips.insert(line.to_string());
            } else {
                self.malicious_domains.insert(line.to_string());
            }
        }
        Ok(())
    }

    fn scan_file(&self, path: &str) -> Option<IOCMatch> {
        let hash = calculate_sha256(path)?;
        if self.malicious_hashes.contains(&hash) {
            return Some(IOCMatch::Hash(path.to_string(), hash));
        }
        None
    }
}

enum IOCMatch {
    Hash(String, String),
    IP(String),
    Domain(String),
}

fn calculate_sha256(path: &str) -> Option<String> {
    // Implementation
    None
}
```

## Detection Rules

### YARA Rule Example
```yara
rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell usage"
        author = "Blue Team"

    strings:
        $enc = "encodedcommand" nocase
        $bypass = "bypass" nocase
        $hidden = "-w hidden" nocase
        $download = "downloadstring" nocase

    condition:
        2 of them
}
```

### Sigma Rule Example
```yaml
title: Suspicious Process Creation
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'bypass'
            - '-enc'
            - 'hidden'
    condition: selection
level: high
```

## Incident Response Workflow

```
1. IDENTIFY
   └─► Detect anomaly via monitoring tools

2. CONTAIN
   └─► Isolate affected systems

3. ERADICATE
   └─► Remove threat

4. RECOVER
   └─► Restore systems

5. LESSONS LEARNED
   └─► Improve defenses
```
