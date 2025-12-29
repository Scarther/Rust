# Chapter 9: Intrusion Detection System Development

## Overview

Build a complete Network Intrusion Detection System (NIDS) in Rust from the ground up.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IDS ARCHITECTURE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐    │
│   │   PACKET    │   │    RULE     │   │     IP      │   │   ALERT     │    │
│   │  CAPTURE    │──▶│   ENGINE    │──▶│ REPUTATION  │──▶│   SYSTEM    │    │
│   │             │   │             │   │             │   │             │    │
│   │ • pcap/AF   │   │ • Parser    │   │ • Blocklist │   │ • Logging   │    │
│   │ • BPF       │   │ • Matcher   │   │ • GeoIP     │   │ • Email     │    │
│   │ • Decode    │   │ • Actions   │   │ • Threat DB │   │ • Webhook   │    │
│   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘    │
│          │                │                 │                 │             │
│          └────────────────┴─────────────────┴─────────────────┘             │
│                                    │                                         │
│                          ┌─────────────────┐                                │
│                          │    IPTABLES     │                                │
│                          │   INTEGRATION   │                                │
│                          │  ───────────    │                                │
│                          │  • Auto-block   │                                │
│                          │  • Rate limit   │                                │
│                          │  • Logging      │                                │
│                          └─────────────────┘                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Sections

| Section | Focus | Key Components |
|---------|-------|----------------|
| [01_Packet_Capture](01_Packet_Capture/) | Network traffic capture | libpcap, AF_PACKET, BPF filters |
| [02_Rule_Engine](02_Rule_Engine/) | Detection rules | Snort-like syntax, pattern matching |
| [03_IP_Reputation](03_IP_Reputation/) | Threat intelligence | Blocklists, scoring, GeoIP |
| [04_Alert_System](04_Alert_System/) | Response and notification | Logging, email, iptables |

## Learning Objectives

By the end of this chapter, you will be able to:
1. Capture and decode network packets in Rust
2. Build a rule-based detection engine
3. Implement IP reputation and threat scoring
4. Create automated response and alerting systems
5. Integrate with iptables for active blocking
6. Build a production-ready IDS

## Prerequisites

- Completed Intermediate Rust projects
- Understanding of TCP/IP networking
- Basic Linux administration (iptables)
- Root access for packet capture

## Key Crates Used

```toml
[dependencies]
pcap = "1.1"                    # Packet capture
pnet = "0.34"                   # Packet parsing
etherparse = "0.13"             # Ethernet frame parsing
regex = "1.10"                  # Pattern matching
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"              # Configuration
tokio = { version = "1", features = ["full"] }  # Async runtime
lettre = "0.11"                 # Email alerts
reqwest = { version = "0.11", features = ["json"] }  # Webhooks
clap = { version = "4.4", features = ["derive"] }
log = "0.4"                     # Logging framework
env_logger = "0.10"             # Logger implementation
```

---

## System Requirements

### Linux Setup
```bash
# Install libpcap development files
sudo apt-get install libpcap-dev

# For iptables integration
sudo apt-get install iptables

# Verify capabilities (alternative to running as root)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rust-ids
```

### Required Permissions
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PERMISSION REQUIREMENTS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Packet Capture:                                                            │
│  • CAP_NET_RAW - Capture raw network packets                                │
│  • CAP_NET_ADMIN - Configure network interfaces                             │
│                                                                              │
│  IPTables Integration:                                                      │
│  • Root access OR CAP_NET_ADMIN                                             │
│  • Write access to /proc/sys/net/ipv4/ip_forward (optional)                │
│                                                                              │
│  Logging:                                                                   │
│  • Write access to log directory                                            │
│  • Syslog access (optional)                                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start: Minimal IDS

Here's a preview of the complete system we'll build:

```rust
//! Minimal IDS - Preview of what you'll build
//!
//! This captures packets and checks them against simple rules

use std::net::IpAddr;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// Represents a captured network packet
///
/// # Fields Explained
/// - `timestamp`: When the packet was captured (Unix epoch microseconds)
/// - `src_ip`: Source IP address
/// - `dst_ip`: Destination IP address
/// - `src_port`: Source port (0 for non-TCP/UDP)
/// - `dst_port`: Destination port
/// - `protocol`: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
/// - `payload`: Raw packet payload
/// - `size`: Total packet size in bytes
#[derive(Debug, Clone)]
struct Packet {
    timestamp: u64,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    payload: Vec<u8>,
    size: usize,
}

/// IDS Detection Rule
///
/// # Rule Anatomy
/// ```text
/// alert tcp any any -> 192.168.1.0/24 22 (msg:"SSH Connection"; sid:1001;)
/// ─┬─── ─┬─ ─┬─ ─┬─   ─────┬──────── ─┬─  ─────────────┬─────────────────
///  │     │   │   │         │          │                │
///  │     │   │   │         │          │                └── Options
///  │     │   │   │         │          └── Destination port
///  │     │   │   │         └── Destination network
///  │     │   │   └── Direction (-> unidirectional, <> bidirectional)
///  │     │   └── Source port
///  │     └── Protocol (tcp, udp, icmp, ip)
///  └── Action (alert, log, drop, pass)
/// ```
#[derive(Debug, Clone)]
struct Rule {
    /// Unique rule identifier
    id: u32,

    /// Rule name/message
    name: String,

    /// Action to take (Alert, Log, Drop)
    action: RuleAction,

    /// Protocol to match
    protocol: Option<Protocol>,

    /// Source IP/network (None = any)
    src_ip: Option<IpNetwork>,

    /// Source port (None = any)
    src_port: Option<PortMatch>,

    /// Destination IP/network
    dst_ip: Option<IpNetwork>,

    /// Destination port
    dst_port: Option<PortMatch>,

    /// Content patterns to match in payload
    content: Vec<ContentMatch>,

    /// Severity level
    severity: Severity,
}

/// What action to take when rule matches
#[derive(Debug, Clone, PartialEq)]
enum RuleAction {
    /// Generate an alert
    Alert,
    /// Log the packet (no alert)
    Log,
    /// Drop the packet (requires inline mode)
    Drop,
    /// Allow packet (whitelist)
    Pass,
}

/// Network protocols we detect
#[derive(Debug, Clone, PartialEq)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
    Any,
}

/// IP network specification (address + optional CIDR)
#[derive(Debug, Clone)]
struct IpNetwork {
    address: IpAddr,
    prefix_len: u8,
}

/// Port matching specification
#[derive(Debug, Clone)]
enum PortMatch {
    /// Match single port
    Single(u16),
    /// Match port range (inclusive)
    Range(u16, u16),
    /// Match any port
    Any,
    /// Match multiple specific ports
    List(Vec<u16>),
}

/// Content pattern to match in payload
#[derive(Debug, Clone)]
struct ContentMatch {
    /// The pattern to match
    pattern: Vec<u8>,
    /// Is this a negated match (match if NOT present)
    negated: bool,
    /// Case insensitive matching
    nocase: bool,
    /// Offset from start of payload
    offset: Option<usize>,
    /// Maximum search depth
    depth: Option<usize>,
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Alert generated when a rule matches
#[derive(Debug, Clone)]
struct Alert {
    /// Timestamp of the alert
    timestamp: u64,
    /// Rule that triggered
    rule_id: u32,
    /// Rule name/message
    message: String,
    /// Source IP
    src_ip: IpAddr,
    /// Destination IP
    dst_ip: IpAddr,
    /// Source port
    src_port: u16,
    /// Destination port
    dst_port: u16,
    /// Protocol
    protocol: String,
    /// Severity
    severity: Severity,
    /// Additional context
    context: String,
}

/// IP reputation entry
#[derive(Debug, Clone)]
struct IpReputation {
    /// The IP address
    address: IpAddr,
    /// Reputation score (0-100, higher = more suspicious)
    score: u32,
    /// Categories this IP belongs to
    categories: Vec<String>,
    /// When this entry was last updated
    last_updated: u64,
    /// Source of the intelligence
    source: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// THE IDS ENGINE
// ═══════════════════════════════════════════════════════════════════════════

/// The main IDS engine that coordinates detection
///
/// # Architecture
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                       IDS Engine                             │
/// │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
/// │  │   Rules     │ │  Blocklist  │ │     Alert Handlers      ││
/// │  │   Vec<Rule> │ │ HashSet<IP> │ │  Vec<Box<dyn Handler>>  ││
/// │  └─────────────┘ └─────────────┘ └─────────────────────────┘│
/// │                                                              │
/// │                    ┌─────────────┐                          │
/// │                    │   Stats     │                          │
/// │                    │  Arc<Mutex> │                          │
/// │                    └─────────────┘                          │
/// └─────────────────────────────────────────────────────────────┘
/// ```
struct IdsEngine {
    /// Detection rules
    rules: Vec<Rule>,

    /// Known malicious IPs (instant block)
    blocklist: HashSet<IpAddr>,

    /// IP reputation database
    reputation: Vec<IpReputation>,

    /// Statistics (thread-safe)
    stats: Arc<Mutex<IdsStats>>,

    /// Alert threshold for reputation
    reputation_threshold: u32,
}

/// IDS Statistics
#[derive(Debug, Default)]
struct IdsStats {
    packets_processed: u64,
    alerts_generated: u64,
    packets_dropped: u64,
    bytes_processed: u64,
}

impl IdsEngine {
    /// Creates a new IDS engine with default settings
    fn new() -> Self {
        IdsEngine {
            rules: Vec::new(),
            blocklist: HashSet::new(),
            reputation: Vec::new(),
            stats: Arc::new(Mutex::new(IdsStats::default())),
            reputation_threshold: 70,
        }
    }

    /// Loads rules from a configuration
    fn load_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
        println!("[*] Loaded {} rules", self.rules.len());
    }

    /// Adds IPs to the blocklist
    fn add_to_blocklist(&mut self, ips: Vec<IpAddr>) {
        for ip in ips {
            self.blocklist.insert(ip);
        }
        println!("[*] Blocklist contains {} IPs", self.blocklist.len());
    }

    /// Processes a single packet
    ///
    /// # Processing Steps
    /// 1. Update statistics
    /// 2. Check blocklist (instant alert)
    /// 3. Check IP reputation
    /// 4. Match against rules
    /// 5. Generate alerts if needed
    fn process_packet(&self, packet: &Packet) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Update stats
        if let Ok(mut stats) = self.stats.lock() {
            stats.packets_processed += 1;
            stats.bytes_processed += packet.size as u64;
        }

        // Step 1: Check blocklist
        if self.blocklist.contains(&packet.src_ip) {
            alerts.push(Alert {
                timestamp: packet.timestamp,
                rule_id: 0,
                message: "Blocklisted IP detected".to_string(),
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                protocol: self.protocol_to_string(packet.protocol),
                severity: Severity::Critical,
                context: "Source IP is on blocklist".to_string(),
            });
        }

        // Step 2: Check IP reputation
        if let Some(rep) = self.get_reputation(&packet.src_ip) {
            if rep.score >= self.reputation_threshold {
                alerts.push(Alert {
                    timestamp: packet.timestamp,
                    rule_id: 0,
                    message: format!("High-risk IP (score: {})", rep.score),
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    protocol: self.protocol_to_string(packet.protocol),
                    severity: Severity::High,
                    context: format!("Categories: {:?}", rep.categories),
                });
            }
        }

        // Step 3: Match against rules
        for rule in &self.rules {
            if self.matches_rule(rule, packet) {
                if rule.action == RuleAction::Alert {
                    alerts.push(Alert {
                        timestamp: packet.timestamp,
                        rule_id: rule.id,
                        message: rule.name.clone(),
                        src_ip: packet.src_ip,
                        dst_ip: packet.dst_ip,
                        src_port: packet.src_port,
                        dst_port: packet.dst_port,
                        protocol: self.protocol_to_string(packet.protocol),
                        severity: rule.severity.clone(),
                        context: String::new(),
                    });
                }
            }
        }

        // Update alert stats
        if !alerts.is_empty() {
            if let Ok(mut stats) = self.stats.lock() {
                stats.alerts_generated += alerts.len() as u64;
            }
        }

        alerts
    }

    /// Checks if a packet matches a rule
    fn matches_rule(&self, rule: &Rule, packet: &Packet) -> bool {
        // Check protocol
        if let Some(ref proto) = rule.protocol {
            if !self.protocol_matches(proto, packet.protocol) {
                return false;
            }
        }

        // Check source IP
        if let Some(ref network) = rule.src_ip {
            if !self.ip_in_network(&packet.src_ip, network) {
                return false;
            }
        }

        // Check destination IP
        if let Some(ref network) = rule.dst_ip {
            if !self.ip_in_network(&packet.dst_ip, network) {
                return false;
            }
        }

        // Check source port
        if let Some(ref port_match) = rule.src_port {
            if !self.port_matches(port_match, packet.src_port) {
                return false;
            }
        }

        // Check destination port
        if let Some(ref port_match) = rule.dst_port {
            if !self.port_matches(port_match, packet.dst_port) {
                return false;
            }
        }

        // Check content patterns
        for content in &rule.content {
            if !self.content_matches(content, &packet.payload) {
                return false;
            }
        }

        true
    }

    /// Checks if protocol matches
    fn protocol_matches(&self, rule_proto: &Protocol, packet_proto: u8) -> bool {
        match rule_proto {
            Protocol::Any => true,
            Protocol::TCP => packet_proto == 6,
            Protocol::UDP => packet_proto == 17,
            Protocol::ICMP => packet_proto == 1,
        }
    }

    /// Checks if IP is in network
    fn ip_in_network(&self, ip: &IpAddr, network: &IpNetwork) -> bool {
        match (ip, &network.address) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from(*ip);
                let net_bits = u32::from(*net);
                let mask = !0u32 << (32 - network.prefix_len);
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from(*ip);
                let net_bits = u128::from(*net);
                let mask = !0u128 << (128 - network.prefix_len);
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false,
        }
    }

    /// Checks if port matches
    fn port_matches(&self, port_match: &PortMatch, port: u16) -> bool {
        match port_match {
            PortMatch::Any => true,
            PortMatch::Single(p) => *p == port,
            PortMatch::Range(start, end) => port >= *start && port <= *end,
            PortMatch::List(ports) => ports.contains(&port),
        }
    }

    /// Checks if content pattern matches payload
    fn content_matches(&self, content: &ContentMatch, payload: &[u8]) -> bool {
        let search_area = if let Some(offset) = content.offset {
            if offset >= payload.len() {
                return content.negated;
            }
            &payload[offset..]
        } else {
            payload
        };

        let search_area = if let Some(depth) = content.depth {
            let end = depth.min(search_area.len());
            &search_area[..end]
        } else {
            search_area
        };

        let pattern = if content.nocase {
            content.pattern.to_ascii_lowercase()
        } else {
            content.pattern.clone()
        };

        let search = if content.nocase {
            search_area.to_ascii_lowercase()
        } else {
            search_area.to_vec()
        };

        let found = search.windows(pattern.len())
            .any(|window| window == pattern.as_slice());

        if content.negated { !found } else { found }
    }

    /// Gets IP reputation
    fn get_reputation(&self, ip: &IpAddr) -> Option<&IpReputation> {
        self.reputation.iter().find(|r| r.address == *ip)
    }

    /// Converts protocol number to string
    fn protocol_to_string(&self, proto: u8) -> String {
        match proto {
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            _ => format!("IP({})", proto),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IPTABLES INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════

/// Manages iptables rules for active response
///
/// # Security Considerations
/// - Requires root or CAP_NET_ADMIN
/// - Be careful not to lock yourself out!
/// - Always have out-of-band access
struct IptablesManager {
    /// Chain to use for our rules
    chain: String,
    /// Maximum number of IPs to block (prevent resource exhaustion)
    max_blocks: usize,
    /// Currently blocked IPs
    blocked: HashSet<IpAddr>,
}

impl IptablesManager {
    fn new(chain: &str) -> Self {
        IptablesManager {
            chain: chain.to_string(),
            max_blocks: 10000,
            blocked: HashSet::new(),
        }
    }

    /// Initializes the IDS chain in iptables
    ///
    /// Creates a dedicated chain for IDS rules:
    /// ```bash
    /// iptables -N IDS_BLOCK
    /// iptables -I INPUT -j IDS_BLOCK
    /// ```
    fn initialize(&self) -> Result<(), String> {
        // Create chain
        let output = std::process::Command::new("iptables")
            .args(["-N", &self.chain])
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;

        // Chain might already exist, that's okay
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Chain already exists") {
                // Continue anyway, might work
            }
        }

        // Insert jump to our chain
        std::process::Command::new("iptables")
            .args(["-C", "INPUT", "-j", &self.chain])
            .output()
            .ok(); // Check if rule exists

        std::process::Command::new("iptables")
            .args(["-I", "INPUT", "-j", &self.chain])
            .output()
            .map_err(|e| format!("Failed to insert jump rule: {}", e))?;

        Ok(())
    }

    /// Blocks an IP address
    ///
    /// ```bash
    /// iptables -A IDS_BLOCK -s <ip> -j DROP
    /// ```
    fn block_ip(&mut self, ip: &IpAddr) -> Result<(), String> {
        if self.blocked.contains(ip) {
            return Ok(()); // Already blocked
        }

        if self.blocked.len() >= self.max_blocks {
            return Err("Maximum block limit reached".to_string());
        }

        let output = std::process::Command::new("iptables")
            .args(["-A", &self.chain, "-s", &ip.to_string(), "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;

        if output.status.success() {
            self.blocked.insert(*ip);
            println!("[+] Blocked IP: {}", ip);
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Unblocks an IP address
    fn unblock_ip(&mut self, ip: &IpAddr) -> Result<(), String> {
        if !self.blocked.contains(ip) {
            return Ok(()); // Not blocked
        }

        let output = std::process::Command::new("iptables")
            .args(["-D", &self.chain, "-s", &ip.to_string(), "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;

        if output.status.success() {
            self.blocked.remove(ip);
            println!("[-] Unblocked IP: {}", ip);
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Flushes all IDS rules
    fn flush(&mut self) -> Result<(), String> {
        std::process::Command::new("iptables")
            .args(["-F", &self.chain])
            .output()
            .map_err(|e| format!("Failed to flush chain: {}", e))?;

        self.blocked.clear();
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║            RUST IDS - Intrusion Detection System                ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Initialize the IDS engine
    let mut engine = IdsEngine::new();

    // Load sample rules
    engine.load_rules(vec![
        Rule {
            id: 1001,
            name: "SSH Connection Attempt".to_string(),
            action: RuleAction::Alert,
            protocol: Some(Protocol::TCP),
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: Some(PortMatch::Single(22)),
            content: vec![],
            severity: Severity::Low,
        },
        Rule {
            id: 1002,
            name: "Potential SQL Injection".to_string(),
            action: RuleAction::Alert,
            protocol: Some(Protocol::TCP),
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: Some(PortMatch::List(vec![80, 443, 8080])),
            content: vec![
                ContentMatch {
                    pattern: b"UNION SELECT".to_vec(),
                    negated: false,
                    nocase: true,
                    offset: None,
                    depth: None,
                },
            ],
            severity: Severity::High,
        },
        Rule {
            id: 1003,
            name: "Potential XSS Attack".to_string(),
            action: RuleAction::Alert,
            protocol: Some(Protocol::TCP),
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: Some(PortMatch::List(vec![80, 443])),
            content: vec![
                ContentMatch {
                    pattern: b"<script>".to_vec(),
                    negated: false,
                    nocase: true,
                    offset: None,
                    depth: None,
                },
            ],
            severity: Severity::Medium,
        },
    ]);

    // Add sample blocklist
    engine.add_to_blocklist(vec![
        "192.0.2.1".parse().unwrap(),  // TEST-NET
        "198.51.100.1".parse().unwrap(),  // TEST-NET-2
    ]);

    println!("\n[*] IDS Engine initialized and ready");
    println!("[*] In a real implementation, this would capture live packets");
    println!("[*] See the individual sections for complete implementations");
}
```

---

## Understanding IDS Concepts

### IDS vs IPS

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IDS vs IPS                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  IDS (Intrusion Detection System)                                           │
│  ─────────────────────────────────                                          │
│  • Passive monitoring                                                        │
│  • Alerts on suspicious activity                                             │
│  • No packet modification                                                    │
│  • Deployed via port mirroring/TAP                                          │
│                                                                              │
│  IPS (Intrusion Prevention System)                                          │
│  ─────────────────────────────────                                          │
│  • Inline deployment                                                         │
│  • Can drop/modify packets                                                   │
│  • Active blocking                                                           │
│  • Higher risk (can cause outages)                                          │
│                                                                              │
│  Our System: Hybrid                                                          │
│  ─────────────────────                                                       │
│  • IDS detection + IPS response via iptables                                │
│  • Detection is passive (packet copy)                                       │
│  • Response is active (firewall rules)                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Detection Methods

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DETECTION METHODS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. SIGNATURE-BASED                                                          │
│     └─► Match known attack patterns                                          │
│     └─► Fast and accurate for known threats                                  │
│     └─► Cannot detect zero-days                                              │
│                                                                              │
│  2. ANOMALY-BASED                                                            │
│     └─► Establish baseline behavior                                          │
│     └─► Detect deviations from normal                                        │
│     └─► Can detect unknown attacks                                           │
│     └─► Higher false positive rate                                           │
│                                                                              │
│  3. REPUTATION-BASED                                                         │
│     └─► Check IP/domain against threat feeds                                 │
│     └─► Quick and lightweight                                                │
│     └─► Depends on feed quality                                              │
│                                                                              │
│  4. PROTOCOL-BASED                                                           │
│     └─► Validate protocol compliance                                         │
│     └─► Detect malformed packets                                             │
│     └─► State tracking                                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Rust Patterns for IDS

### Pattern 1: Zero-Copy Packet Processing

```rust
/// Process packets without copying data
///
/// # Why Zero-Copy?
/// Network IDS must process thousands of packets per second.
/// Copying packet data for each operation wastes CPU and memory.
fn process_packet_zero_copy<'a>(packet: &'a [u8]) -> Option<PacketHeader<'a>> {
    // Parse header without copying
    if packet.len() < 20 {
        return None;
    }

    Some(PacketHeader {
        data: packet,
        ip_header_len: ((packet[0] & 0x0F) * 4) as usize,
    })
}

struct PacketHeader<'a> {
    data: &'a [u8],  // Borrows original data
    ip_header_len: usize,
}

impl<'a> PacketHeader<'a> {
    fn src_ip(&self) -> [u8; 4] {
        // Return slice of original data
        [self.data[12], self.data[13], self.data[14], self.data[15]]
    }
}
```

### Pattern 2: Lock-Free Statistics

```rust
use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe statistics without locks
///
/// # Why Atomic?
/// Locks (Mutex) cause contention in high-throughput scenarios.
/// Atomic operations are lock-free and scale better.
struct LockFreeStats {
    packets: AtomicU64,
    bytes: AtomicU64,
    alerts: AtomicU64,
}

impl LockFreeStats {
    fn new() -> Self {
        LockFreeStats {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            alerts: AtomicU64::new(0),
        }
    }

    fn record_packet(&self, size: u64) {
        // Relaxed ordering is fine for statistics
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(size, Ordering::Relaxed);
    }

    fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.packets.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.alerts.load(Ordering::Relaxed),
        )
    }
}
```

### Pattern 3: Async Alert Handling

```rust
use tokio::sync::mpsc;

/// Asynchronous alert processing
///
/// # Why Async?
/// Alert handling (email, webhook, database) is I/O bound.
/// Async allows processing alerts without blocking packet capture.
async fn alert_handler(mut rx: mpsc::Receiver<Alert>) {
    while let Some(alert) = rx.recv().await {
        // Process alert asynchronously
        tokio::spawn(async move {
            // Send email
            send_email_alert(&alert).await;
            // Send to SIEM
            send_to_siem(&alert).await;
            // Log to file
            log_alert(&alert).await;
        });
    }
}

async fn send_email_alert(alert: &Alert) {
    // Email sending implementation
}

async fn send_to_siem(alert: &Alert) {
    // SIEM API call
}

async fn log_alert(alert: &Alert) {
    // Async file logging
}
```

---

Continue to the specific sections for detailed implementations.

[→ 01_Packet_Capture](01_Packet_Capture/) | [→ 02_Rule_Engine](02_Rule_Engine/) | [→ 03_IP_Reputation](03_IP_Reputation/) | [→ 04_Alert_System](04_Alert_System/)
