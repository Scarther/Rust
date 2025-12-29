# Case Study 01: The Compromised Server

## Scenario

**Date:** Monday, 9:47 AM
**Alert:** SOC receives multiple alerts about unusual outbound connections from production server PROD-WEB-03.

**Initial Findings:**
- Server handling customer web traffic
- Unusual DNS queries to suspicious domains
- Spike in CPU usage during off-hours
- Modified system binaries suspected

**Your Mission:** Build a Rust-based incident response toolkit to investigate and document findings.

---

## Requirements Analysis

### Functional Requirements

1. **IOC Scanner** - Search for known indicators of compromise
2. **Hash Verifier** - Verify system binary integrity
3. **Log Analyzer** - Parse and analyze system logs
4. **Network Monitor** - Capture suspicious connections
5. **Report Generator** - Document findings

### Non-Functional Requirements

- Run without installing dependencies (static binary)
- Minimal system footprint
- Cross-platform (Linux primary)
- Fast execution for time-sensitive IR

---

## Design Decisions

### Architecture Overview

```
┌─────────────────────────────────────────────────┐
│               IR Toolkit CLI                     │
├─────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐│
│  │   IOC   │ │  Hash   │ │   Log   │ │Network ││
│  │ Scanner │ │Verifier │ │Analyzer │ │Monitor ││
│  └────┬────┘ └────┬────┘ └────┬────┘ └───┬────┘│
│       │          │          │           │      │
│       └──────────┴──────────┴───────────┘      │
│                      │                          │
│              ┌───────┴───────┐                  │
│              │ Report Engine │                  │
│              └───────────────┘                  │
└─────────────────────────────────────────────────┘
```

### Key Design Choices

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Build System | Cargo with musl | Static binary, no runtime deps |
| CLI Framework | clap | Feature-rich, well-documented |
| Hashing | sha2 crate | Pure Rust, audited |
| Async Runtime | tokio | Network operations |
| Output Format | JSON + Markdown | Machine + human readable |

---

## Implementation

### Project Structure

```
ir_toolkit/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── ioc/
│   │   ├── mod.rs
│   │   ├── scanner.rs
│   │   └── indicators.rs
│   ├── hash/
│   │   ├── mod.rs
│   │   └── verifier.rs
│   ├── logs/
│   │   ├── mod.rs
│   │   └── analyzer.rs
│   ├── network/
│   │   ├── mod.rs
│   │   └── monitor.rs
│   └── report/
│       ├── mod.rs
│       └── generator.rs
```

### Cargo.toml

```toml
[package]
name = "ir_toolkit"
version = "1.0.0"
edition = "2021"
description = "Incident Response Toolkit"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
tokio = { version = "1.34", features = ["full"] }
sha2 = "0.10"
hex = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
walkdir = "2.4"
regex = "1.10"
chrono = { version = "0.4", features = ["serde"] }
colored = "2.0"

[profile.release]
opt-level = "z"
lto = true
strip = true
panic = "abort"
```

### Core CLI (main.rs)

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod ioc;
mod hash;
mod logs;
mod network;
mod report;

#[derive(Parser)]
#[command(name = "ir_toolkit")]
#[command(about = "Incident Response Toolkit for Security Investigations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (json, text, markdown)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Output file path
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for indicators of compromise
    Ioc {
        /// Path to scan
        #[arg(short, long, default_value = "/")]
        path: PathBuf,

        /// IOC database file
        #[arg(short, long)]
        indicators: Option<PathBuf>,
    },

    /// Verify file hashes against known good
    Hash {
        /// Path to scan
        #[arg(short, long)]
        path: PathBuf,

        /// Hash database file
        #[arg(short, long)]
        database: PathBuf,
    },

    /// Analyze log files
    Logs {
        /// Log file or directory
        #[arg(short, long)]
        path: PathBuf,

        /// Time range start (ISO 8601)
        #[arg(long)]
        start: Option<String>,

        /// Time range end (ISO 8601)
        #[arg(long)]
        end: Option<String>,
    },

    /// Monitor network connections
    Network {
        /// Interface to monitor
        #[arg(short, long, default_value = "eth0")]
        interface: String,

        /// Duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
    },

    /// Generate investigation report
    Report {
        /// Findings directory
        #[arg(short, long)]
        findings: PathBuf,

        /// Report title
        #[arg(short, long, default_value = "Incident Response Report")]
        title: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ioc { path, indicators } => {
            ioc::scan(&path, indicators.as_deref()).await?;
        }
        Commands::Hash { path, database } => {
            hash::verify(&path, &database)?;
        }
        Commands::Logs { path, start, end } => {
            logs::analyze(&path, start.as_deref(), end.as_deref())?;
        }
        Commands::Network { interface, duration } => {
            network::monitor(&interface, duration).await?;
        }
        Commands::Report { findings, title } => {
            report::generate(&findings, &title)?;
        }
    }

    Ok(())
}
```

### IOC Scanner Module (ioc/scanner.rs)

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;
use regex::Regex;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct IocDatabase {
    pub file_hashes: HashSet<String>,
    pub ip_addresses: HashSet<String>,
    pub domains: HashSet<String>,
    pub file_paths: HashSet<String>,
    pub registry_keys: HashSet<String>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub ioc_type: String,
    pub indicator: String,
    pub location: String,
    pub severity: String,
    pub timestamp: String,
}

pub async fn scan(path: &Path, ioc_db: Option<&Path>) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Load IOC database
    let db = match ioc_db {
        Some(p) => load_database(p)?,
        None => default_database(),
    };

    println!("[*] Starting IOC scan of {:?}", path);

    // Scan filesystem
    for entry in WalkDir::new(path)
        .follow_links(false)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let file_path = entry.path();

        // Check path against known bad paths
        let path_str = file_path.to_string_lossy();
        for bad_path in &db.file_paths {
            if path_str.contains(bad_path) {
                findings.push(Finding {
                    ioc_type: "suspicious_path".to_string(),
                    indicator: bad_path.clone(),
                    location: path_str.to_string(),
                    severity: "high".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Check file contents for IOCs
        if file_path.is_file() {
            if let Ok(content) = fs::read_to_string(file_path) {
                // Check for suspicious IPs
                let ip_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")?;
                for cap in ip_regex.captures_iter(&content) {
                    let ip = cap.get(0).unwrap().as_str();
                    if db.ip_addresses.contains(ip) {
                        findings.push(Finding {
                            ioc_type: "malicious_ip".to_string(),
                            indicator: ip.to_string(),
                            location: path_str.to_string(),
                            severity: "critical".to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }

                // Check for suspicious domains
                for domain in &db.domains {
                    if content.contains(domain) {
                        findings.push(Finding {
                            ioc_type: "malicious_domain".to_string(),
                            indicator: domain.clone(),
                            location: path_str.to_string(),
                            severity: "critical".to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        // Check file hash
        if file_path.is_file() {
            if let Ok(hash) = compute_file_hash(file_path) {
                if db.file_hashes.contains(&hash) {
                    findings.push(Finding {
                        ioc_type: "malicious_hash".to_string(),
                        indicator: hash,
                        location: path_str.to_string(),
                        severity: "critical".to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }
    }

    println!("[+] Scan complete. Found {} indicators.", findings.len());
    Ok(findings)
}

fn compute_file_hash(path: &Path) -> anyhow::Result<String> {
    use sha2::{Sha256, Digest};

    let content = fs::read(path)?;
    let hash = Sha256::digest(&content);
    Ok(hex::encode(hash))
}

fn load_database(path: &Path) -> anyhow::Result<IocDatabase> {
    let content = fs::read_to_string(path)?;
    let db: IocDatabase = serde_json::from_str(&content)?;
    Ok(db)
}

fn default_database() -> IocDatabase {
    IocDatabase {
        file_hashes: HashSet::new(),
        ip_addresses: [
            // Example known bad IPs (for demonstration)
            "10.0.0.1".to_string(),
        ].into_iter().collect(),
        domains: [
            // Example known bad domains (for demonstration)
            "malware-c2.example.com".to_string(),
        ].into_iter().collect(),
        file_paths: [
            "/tmp/.hidden".to_string(),
            "/.backdoor".to_string(),
            "/var/tmp/.cache".to_string(),
        ].into_iter().collect(),
        registry_keys: HashSet::new(),
    }
}
```

### Hash Verifier Module (hash/verifier.rs)

```rust
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Serialize, Deserialize)]
pub struct HashDatabase {
    pub files: HashMap<String, String>, // path -> expected hash
}

#[derive(Debug, Serialize)]
pub struct HashResult {
    pub path: String,
    pub status: String, // "match", "mismatch", "missing", "new"
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
}

pub fn verify(path: &Path, database: &Path) -> anyhow::Result<Vec<HashResult>> {
    let mut results = Vec::new();

    // Load hash database
    let db_content = fs::read_to_string(database)?;
    let db: HashDatabase = serde_json::from_str(&db_content)?;

    println!("[*] Verifying file integrity in {:?}", path);

    let mut found_files: HashMap<String, String> = HashMap::new();

    // Scan and hash files
    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let file_path = entry.path();
        if !file_path.is_file() {
            continue;
        }

        let path_str = file_path.to_string_lossy().to_string();

        if let Ok(hash) = compute_hash(file_path) {
            found_files.insert(path_str.clone(), hash.clone());

            if let Some(expected) = db.files.get(&path_str) {
                if &hash == expected {
                    results.push(HashResult {
                        path: path_str,
                        status: "match".to_string(),
                        expected_hash: Some(expected.clone()),
                        actual_hash: Some(hash),
                    });
                } else {
                    println!("[!] MISMATCH: {}", path_str);
                    results.push(HashResult {
                        path: path_str,
                        status: "mismatch".to_string(),
                        expected_hash: Some(expected.clone()),
                        actual_hash: Some(hash),
                    });
                }
            } else {
                results.push(HashResult {
                    path: path_str,
                    status: "new".to_string(),
                    expected_hash: None,
                    actual_hash: Some(hash),
                });
            }
        }
    }

    // Check for missing files
    for (expected_path, expected_hash) in &db.files {
        if !found_files.contains_key(expected_path) {
            println!("[!] MISSING: {}", expected_path);
            results.push(HashResult {
                path: expected_path.clone(),
                status: "missing".to_string(),
                expected_hash: Some(expected_hash.clone()),
                actual_hash: None,
            });
        }
    }

    let mismatches: Vec<_> = results.iter()
        .filter(|r| r.status == "mismatch")
        .collect();

    println!("\n[+] Verification complete:");
    println!("    Total files: {}", results.len());
    println!("    Mismatches: {}", mismatches.len());

    Ok(results)
}

fn compute_hash(path: &Path) -> anyhow::Result<String> {
    let content = fs::read(path)?;
    let hash = Sha256::digest(&content);
    Ok(hex::encode(hash))
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hash_computation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello world").unwrap();

        let hash = compute_hash(&file_path).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_ioc_domain_detection() {
        let content = "config = { server: 'malware-c2.example.com' }";
        let db = default_database();

        let mut found = false;
        for domain in &db.domains {
            if content.contains(domain) {
                found = true;
                break;
            }
        }

        assert!(found);
    }
}
```

### Integration Tests

```rust
// tests/integration_tests.rs
use std::process::Command;

#[test]
fn test_cli_ioc_scan() {
    let output = Command::new("cargo")
        .args(["run", "--", "ioc", "--path", "/tmp"])
        .output()
        .expect("Failed to run command");

    assert!(output.status.success());
}

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to run command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Incident Response Toolkit"));
}
```

---

## Deployment Considerations

### Building for Production

```bash
# Build static Linux binary
cargo build --release --target x86_64-unknown-linux-musl

# Verify binary
file target/x86_64-unknown-linux-musl/release/ir_toolkit
# Should show: statically linked

# Check size
ls -lh target/x86_64-unknown-linux-musl/release/ir_toolkit
```

### Distribution

```bash
# Create distribution package
mkdir -p dist/ir_toolkit
cp target/x86_64-unknown-linux-musl/release/ir_toolkit dist/ir_toolkit/
cp README.md dist/ir_toolkit/
cp -r sample_iocs/ dist/ir_toolkit/

# Create archive
tar -czvf ir_toolkit-linux-x64.tar.gz -C dist ir_toolkit
```

### Usage in Incident Response

```bash
# Quick IOC scan
./ir_toolkit ioc --path /var/www

# Verify system binaries
./ir_toolkit hash --path /usr/bin --database known_good_hashes.json

# Analyze auth logs
./ir_toolkit logs --path /var/log/auth.log --start "2024-01-15T00:00:00Z"

# Generate report
./ir_toolkit report --findings ./findings/ --title "PROD-WEB-03 Investigation"
```

---

## Lessons Learned

### Technical Insights

1. **Static Compilation is Essential** - IR tools must run without dependencies
2. **Memory Safety Matters** - Rust prevents crashes during critical investigations
3. **Async for Network Ops** - Concurrent scanning significantly speeds up IR
4. **Structured Output** - JSON output enables integration with SIEM systems

### Process Insights

1. **Pre-built Toolkits Save Time** - Have tools ready before incidents occur
2. **Document Everything** - Automated reporting ensures evidence integrity
3. **Test in Lab First** - Validate tools against simulated scenarios
4. **Keep Tools Updated** - Regular IOC database updates are critical

### What Went Well

- Rust's zero-copy parsing made log analysis fast
- Single binary deployment simplified evidence collection
- Type system caught several edge cases during development

### What Could Be Improved

- Add more output formats (CSV, STIX)
- Implement memory-resident artifact scanning
- Add YARA rule support for more flexible IOC matching

---

## MITRE ATT&CK Mapping

| Tool Function | Detects Techniques |
|---------------|-------------------|
| IOC Scanner | T1071 (App Layer Protocol), T1041 (Exfiltration) |
| Hash Verifier | T1036 (Masquerading), T1574 (Hijack Execution) |
| Log Analyzer | T1078 (Valid Accounts), T1110 (Brute Force) |
| Network Monitor | T1071 (C2), T1048 (Exfiltration Over C2) |

---

## Further Reading

- [NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [Rust Security Best Practices](https://anssi-fr.github.io/rust-guide/)

---

[← Back to Case Studies](./README.md) | [Next: CS02 - Data Breach Hunt →](./CS02_Data_Breach_Hunt.md)
