# Case Study 02: The Data Breach Hunt

## Scenario

**Date:** Wednesday, 2:15 PM
**Alert:** Threat intelligence indicates customer data from your organization is being sold on a dark web forum.

**Initial Findings:**
- Data appears to be from the last 30 days
- Contains customer emails, hashed passwords, order history
- Source is unknown - could be any of 12 production systems
- Must identify the breach point without alerting the attacker

**Your Mission:** Build a Rust-based data exfiltration detection toolkit to identify the breach source.

---

## Requirements Analysis

### Investigation Goals

1. **Network Analysis** - Identify unusual outbound data transfers
2. **Log Correlation** - Cross-reference access logs from all 12 systems
3. **Data Flow Mapping** - Track where customer data travels
4. **Timeline Reconstruction** - Build a timeline of suspicious activity
5. **Evidence Preservation** - Collect and hash all relevant artifacts

### Tool Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| PCAP analysis | High | Parse network captures |
| Log aggregation | High | Handle multiple log formats |
| Pattern detection | High | Find data exfil patterns |
| Timeline generation | Medium | Correlate events |
| Stealth operation | Medium | Don't alert adversary |

---

## Design Decisions

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Data Breach Hunter Framework               │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Network    │  │     Log      │  │   Pattern    │  │
│  │   Analyzer   │  │  Aggregator  │  │   Matcher    │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                  │          │
│         └────────────┬────┴──────────────────┘          │
│                      │                                   │
│              ┌───────┴───────┐                          │
│              │  Correlation  │                          │
│              │    Engine     │                          │
│              └───────┬───────┘                          │
│                      │                                   │
│              ┌───────┴───────┐                          │
│              │   Timeline    │                          │
│              │   Generator   │                          │
│              └───────────────┘                          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Design Rationale

| Component | Crate | Why |
|-----------|-------|-----|
| PCAP Parsing | pcap, etherparse | Low-level packet access |
| Log Parsing | regex, nom | Flexible format handling |
| Data Matching | aho-corasick | Fast multi-pattern search |
| Time Handling | chrono | Timezone-aware timestamps |
| Parallelism | rayon | Parallel file processing |

---

## Implementation

### Project Setup

```toml
[package]
name = "breach_hunter"
version = "1.0.0"
edition = "2021"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
tokio = { version = "1.34", features = ["full"] }
pcap = "1.1"
etherparse = "0.14"
regex = "1.10"
aho-corasick = "1.1"
rayon = "1.8"
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
walkdir = "2.4"
csv = "1.3"
indicatif = "0.17"

[profile.release]
opt-level = 3
lto = true
```

### Network Analyzer

```rust
use etherparse::{SlicedPacket, TransportSlice};
use pcap::Capture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Serialize, Clone)]
pub struct DataFlow {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub payload_preview: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NetworkAnalysis {
    pub total_flows: usize,
    pub suspicious_flows: Vec<DataFlow>,
    pub top_destinations: Vec<(String, u64)>,
    pub data_volume_by_hour: HashMap<String, u64>,
}

pub fn analyze_pcap(path: &Path) -> anyhow::Result<NetworkAnalysis> {
    let mut cap = Capture::from_file(path)?;
    let mut flows: Vec<DataFlow> = Vec::new();
    let mut dest_bytes: HashMap<String, u64> = HashMap::new();
    let mut hourly_volume: HashMap<String, u64> = HashMap::new();

    println!("[*] Analyzing PCAP: {:?}", path);

    while let Ok(packet) = cap.next_packet() {
        if let Ok(sliced) = SlicedPacket::from_ethernet(&packet.data) {
            let (src_ip, dst_ip) = match sliced.ip {
                Some(etherparse::InternetSlice::Ipv4(ip, _)) => {
                    (
                        format!("{}", ip.source_addr()),
                        format!("{}", ip.destination_addr()),
                    )
                }
                Some(etherparse::InternetSlice::Ipv6(ip, _)) => {
                    (
                        format!("{}", ip.source_addr()),
                        format!("{}", ip.destination_addr()),
                    )
                }
                None => continue,
            };

            let (src_port, dst_port, protocol) = match sliced.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    (tcp.source_port(), tcp.destination_port(), "TCP")
                }
                Some(TransportSlice::Udp(udp)) => {
                    (udp.source_port(), udp.destination_port(), "UDP")
                }
                _ => continue,
            };

            let payload_len = sliced.payload.len() as u64;

            // Track destination volumes
            *dest_bytes.entry(dst_ip.clone()).or_insert(0) += payload_len;

            // Create flow record
            let flow = DataFlow {
                timestamp: chrono::Utc::now().to_rfc3339(), // Would use packet timestamp
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: protocol.to_string(),
                bytes_sent: payload_len,
                payload_preview: extract_preview(sliced.payload),
            };

            flows.push(flow);
        }
    }

    // Find suspicious flows (large outbound, unusual ports, etc.)
    let suspicious: Vec<DataFlow> = flows
        .iter()
        .filter(|f| is_suspicious(f))
        .cloned()
        .collect();

    // Sort destinations by volume
    let mut top_dests: Vec<(String, u64)> = dest_bytes.into_iter().collect();
    top_dests.sort_by(|a, b| b.1.cmp(&a.1));
    top_dests.truncate(20);

    println!("[+] Analysis complete. {} suspicious flows found.", suspicious.len());

    Ok(NetworkAnalysis {
        total_flows: flows.len(),
        suspicious_flows: suspicious,
        top_destinations: top_dests,
        data_volume_by_hour: hourly_volume,
    })
}

fn is_suspicious(flow: &DataFlow) -> bool {
    // Suspicious criteria:
    // 1. Large data transfers (> 10MB)
    // 2. Unusual ports
    // 3. Known bad destinations
    // 4. Encrypted data to unusual destinations

    let suspicious_ports = [4444, 5555, 6666, 8888, 9999, 1337, 31337];
    let large_transfer_threshold = 10 * 1024 * 1024; // 10 MB

    flow.bytes_sent > large_transfer_threshold
        || suspicious_ports.contains(&flow.dst_port)
        || is_known_bad_ip(&flow.dst_ip)
}

fn is_known_bad_ip(_ip: &str) -> bool {
    // Check against threat intel database
    // Placeholder for actual implementation
    false
}

fn extract_preview(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }

    // Only return preview if it's printable ASCII
    let preview: String = payload
        .iter()
        .take(50)
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect();

    Some(preview)
}
```

### Log Aggregator

```rust
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::WalkDir;
use rayon::prelude::*;

#[derive(Debug, Serialize, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub log_type: String,
    pub user: Option<String>,
    pub action: String,
    pub details: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct AggregatedLogs {
    pub total_entries: usize,
    pub entries_by_source: HashMap<String, usize>,
    pub entries_by_severity: HashMap<String, usize>,
    pub timeline: Vec<LogEntry>,
    pub suspicious_entries: Vec<LogEntry>,
}

pub fn aggregate_logs(log_dirs: &[&Path]) -> anyhow::Result<AggregatedLogs> {
    let mut all_entries: Vec<LogEntry> = Vec::new();

    // Define log format patterns
    let patterns = LogPatterns::new()?;

    for dir in log_dirs {
        println!("[*] Scanning log directory: {:?}", dir);

        let files: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| {
                let ext = e.path().extension().and_then(|s| s.to_str());
                matches!(ext, Some("log") | Some("txt") | None)
            })
            .collect();

        // Process files in parallel
        let entries: Vec<LogEntry> = files
            .par_iter()
            .flat_map(|entry| parse_log_file(entry.path(), &patterns).unwrap_or_default())
            .collect();

        all_entries.extend(entries);
    }

    // Sort by timestamp
    all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Aggregate statistics
    let mut by_source: HashMap<String, usize> = HashMap::new();
    let mut by_severity: HashMap<String, usize> = HashMap::new();

    for entry in &all_entries {
        *by_source.entry(entry.source.clone()).or_insert(0) += 1;
        *by_severity.entry(entry.severity.clone()).or_insert(0) += 1;
    }

    // Find suspicious entries
    let suspicious: Vec<LogEntry> = all_entries
        .iter()
        .filter(|e| is_suspicious_log(e))
        .cloned()
        .collect();

    println!("[+] Aggregated {} log entries.", all_entries.len());

    Ok(AggregatedLogs {
        total_entries: all_entries.len(),
        entries_by_source: by_source,
        entries_by_severity: by_severity,
        timeline: all_entries,
        suspicious_entries: suspicious,
    })
}

struct LogPatterns {
    syslog: Regex,
    apache_access: Regex,
    apache_error: Regex,
    auth: Regex,
    json: Regex,
}

impl LogPatterns {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            syslog: Regex::new(
                r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$"
            )?,
            apache_access: Regex::new(
                r#"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)"#
            )?,
            apache_error: Regex::new(
                r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$"
            )?,
            auth: Regex::new(
                r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+)\[?\d*\]?:\s+(.*)$"
            )?,
            json: Regex::new(r"^\{.*\}$")?,
        })
    }
}

fn parse_log_file(path: &Path, patterns: &LogPatterns) -> anyhow::Result<Vec<LogEntry>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let source = path.to_string_lossy().to_string();

    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(entry) = parse_line(&line, &source, patterns) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

fn parse_line(line: &str, source: &str, patterns: &LogPatterns) -> Option<LogEntry> {
    // Try different patterns

    // Try auth log format
    if let Some(caps) = patterns.auth.captures(line) {
        let action = caps.get(2).map_or("", |m| m.as_str());
        let details = caps.get(3).map_or("", |m| m.as_str());

        return Some(LogEntry {
            timestamp: Utc::now(), // Would parse actual timestamp
            source: source.to_string(),
            log_type: "auth".to_string(),
            user: extract_user(details),
            action: action.to_string(),
            details: details.to_string(),
            severity: classify_severity(details),
        });
    }

    // Try Apache access log
    if let Some(caps) = patterns.apache_access.captures(line) {
        let user = caps.get(2).map(|m| m.as_str().to_string());
        let request = caps.get(4).map_or("", |m| m.as_str());

        return Some(LogEntry {
            timestamp: Utc::now(),
            source: source.to_string(),
            log_type: "access".to_string(),
            user: if user.as_deref() == Some("-") { None } else { user },
            action: "http_request".to_string(),
            details: request.to_string(),
            severity: "info".to_string(),
        });
    }

    None
}

fn extract_user(details: &str) -> Option<String> {
    // Extract username from log details
    let user_patterns = [
        r"user=(\S+)",
        r"for (\S+)",
        r"User (\S+)",
        r"user '([^']+)'",
    ];

    for pattern in user_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(details) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
    }

    None
}

fn classify_severity(details: &str) -> String {
    let lower = details.to_lowercase();

    if lower.contains("failed") || lower.contains("error") || lower.contains("denied") {
        "warning".to_string()
    } else if lower.contains("invalid") || lower.contains("attack") || lower.contains("exploit") {
        "critical".to_string()
    } else {
        "info".to_string()
    }
}

fn is_suspicious_log(entry: &LogEntry) -> bool {
    let suspicious_patterns = [
        "failed password",
        "invalid user",
        "break-in attempt",
        "unauthorized",
        "sql injection",
        "xss",
        "directory traversal",
        "etc/passwd",
        "select * from",
        "union select",
        "curl",
        "wget",
    ];

    let details_lower = entry.details.to_lowercase();

    suspicious_patterns.iter().any(|p| details_lower.contains(p))
}
```

### Pattern Matcher for Data Leakage

```rust
use aho_corasick::AhoCorasick;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct DataLeakFinding {
    pub file_path: String,
    pub line_number: usize,
    pub pattern_type: String,
    pub matched_value: String,
    pub context: String,
}

pub struct DataPatterns {
    email: regex::Regex,
    credit_card: regex::Regex,
    ssn: regex::Regex,
    phone: regex::Regex,
    api_key: regex::Regex,
    custom_keywords: AhoCorasick,
}

impl DataPatterns {
    pub fn new(keywords: &[&str]) -> anyhow::Result<Self> {
        Ok(Self {
            email: regex::Regex::new(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            )?,
            credit_card: regex::Regex::new(
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
            )?,
            ssn: regex::Regex::new(
                r"\b\d{3}-\d{2}-\d{4}\b"
            )?,
            phone: regex::Regex::new(
                r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
            )?,
            api_key: regex::Regex::new(
                r"\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?"
            )?,
            custom_keywords: AhoCorasick::new(keywords)?,
        })
    }
}

pub fn scan_for_data_patterns(
    path: &Path,
    patterns: &DataPatterns,
) -> anyhow::Result<Vec<DataLeakFinding>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut findings = Vec::new();
    let file_path = path.to_string_lossy().to_string();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let line_number = line_num + 1;

        // Check for emails
        for mat in patterns.email.find_iter(&line) {
            findings.push(DataLeakFinding {
                file_path: file_path.clone(),
                line_number,
                pattern_type: "email".to_string(),
                matched_value: redact(mat.as_str()),
                context: get_context(&line, mat.start(), mat.end()),
            });
        }

        // Check for credit cards
        for mat in patterns.credit_card.find_iter(&line) {
            findings.push(DataLeakFinding {
                file_path: file_path.clone(),
                line_number,
                pattern_type: "credit_card".to_string(),
                matched_value: redact_cc(mat.as_str()),
                context: get_context(&line, mat.start(), mat.end()),
            });
        }

        // Check for SSNs
        for mat in patterns.ssn.find_iter(&line) {
            findings.push(DataLeakFinding {
                file_path: file_path.clone(),
                line_number,
                pattern_type: "ssn".to_string(),
                matched_value: "XXX-XX-XXXX".to_string(),
                context: get_context(&line, mat.start(), mat.end()),
            });
        }

        // Check for API keys
        for caps in patterns.api_key.captures_iter(&line) {
            if let Some(key) = caps.get(1) {
                findings.push(DataLeakFinding {
                    file_path: file_path.clone(),
                    line_number,
                    pattern_type: "api_key".to_string(),
                    matched_value: format!("{}...", &key.as_str()[..8]),
                    context: get_context(&line, key.start(), key.end()),
                });
            }
        }

        // Check custom keywords
        for mat in patterns.custom_keywords.find_iter(&line) {
            findings.push(DataLeakFinding {
                file_path: file_path.clone(),
                line_number,
                pattern_type: "keyword".to_string(),
                matched_value: mat.pattern().to_string(),
                context: get_context(&line, mat.start(), mat.end()),
            });
        }
    }

    Ok(findings)
}

fn redact(s: &str) -> String {
    // Redact middle portion of sensitive data
    if s.len() > 6 {
        format!("{}...{}", &s[..3], &s[s.len()-3..])
    } else {
        "***".to_string()
    }
}

fn redact_cc(s: &str) -> String {
    // Show only last 4 digits
    format!("****-****-****-{}", &s[s.len()-4..])
}

fn get_context(line: &str, start: usize, end: usize) -> String {
    // Get surrounding context
    let ctx_start = start.saturating_sub(20);
    let ctx_end = (end + 20).min(line.len());

    format!("...{}...", &line[ctx_start..ctx_end])
}
```

---

## Testing Strategy

### Test Environment Setup

```bash
# Create test data with simulated sensitive info
mkdir -p test_data/logs test_data/pcaps

# Generate test logs
cat > test_data/logs/auth.log << 'EOF'
Jan 15 10:23:45 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22
Jan 15 10:23:46 server sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22
Jan 15 10:24:00 server sshd[1234]: Accepted publickey for developer from 10.0.0.5 port 22
Jan 15 14:30:00 server sshd[5678]: session opened for user www-data by (uid=0)
EOF

# Generate test file with "leaked" data
cat > test_data/leaked.txt << 'EOF'
customer_email: john.doe@example.com
api_key: sk_live_abcdefghijk1234567890
credit_card: 4111111111111111
ssn: 123-45-6789
EOF
```

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_pattern() {
        let patterns = DataPatterns::new(&[]).unwrap();
        let emails = patterns.email.find_iter("Contact: user@example.com or admin@test.org");
        assert_eq!(emails.count(), 2);
    }

    #[test]
    fn test_suspicious_log_detection() {
        let entry = LogEntry {
            timestamp: Utc::now(),
            source: "test".to_string(),
            log_type: "auth".to_string(),
            user: None,
            action: "sshd".to_string(),
            details: "Failed password for invalid user admin".to_string(),
            severity: "warning".to_string(),
        };

        assert!(is_suspicious_log(&entry));
    }

    #[test]
    fn test_cc_detection() {
        let patterns = DataPatterns::new(&[]).unwrap();
        let test = "Card: 4111111111111111";
        assert!(patterns.credit_card.is_match(test));
    }
}
```

---

## Deployment

### Building

```bash
# Standard release build
cargo build --release

# With verbose output for debugging
RUST_LOG=debug cargo run --release -- scan --path /var/log
```

### Usage Examples

```bash
# Analyze network captures
./breach_hunter network --pcap /path/to/capture.pcap --output suspicious_flows.json

# Aggregate and analyze logs
./breach_hunter logs --dirs /var/log,/opt/app/logs --start "2024-01-01" --end "2024-01-31"

# Scan for data patterns
./breach_hunter scan --path /home --patterns "customer_id,order_number" --output findings.json

# Generate timeline
./breach_hunter timeline --sources logs.json,network.json --output timeline.html
```

---

## Lessons Learned

### Key Findings from Investigation

1. **Parallel Processing Essential** - Log files can be massive; rayon made analysis feasible
2. **Pattern Libraries Help** - Aho-Corasick for fast multi-pattern matching
3. **Timestamp Normalization Critical** - Different log formats have different timestamp formats
4. **Memory Efficiency Matters** - Stream processing vs loading entire files

### Tool Improvements Identified

- Add support for compressed logs (gzip, bzip2)
- Implement incremental analysis for ongoing monitoring
- Add PCAP reassembly for TCP streams
- Create visualization dashboard

### Incident Response Insights

- Data was exfiltrated via DNS tunneling (missed initially)
- Attacker used legitimate credentials obtained via phishing
- Exfiltration occurred during business hours to blend in
- Multiple small transfers avoided volume-based detection

---

## MITRE ATT&CK Mapping

| Detection Focus | MITRE Technique |
|-----------------|-----------------|
| Large outbound transfers | T1048 - Exfiltration Over Alternative Protocol |
| DNS query analysis | T1071.004 - DNS |
| Failed login attempts | T1110 - Brute Force |
| Data staging detection | T1074 - Data Staged |
| Credential access logs | T1078 - Valid Accounts |

---

[← CS01: Compromised Server](./CS01_Compromised_Server.md) | [Back to Case Studies](./README.md) | [CS03: Red Team Tool →](./CS03_Red_Team_Tool.md)
