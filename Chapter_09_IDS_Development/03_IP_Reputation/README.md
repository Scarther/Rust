# IDS03: IP Reputation and IPTables Integration

## Overview

| Property | Value |
|----------|-------|
| **ID** | IDS03 |
| **Difficulty** | Advanced |
| **Skills** | Threat intelligence, iptables, system administration |
| **Prerequisites** | IDS01, IDS02, Linux admin basics |
| **Crates** | reqwest, serde, tokio |

## What You'll Learn

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IP REPUTATION SYSTEM                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │  THREAT FEEDS   │     │    SCORING      │     │    IPTABLES     │       │
│  │  ───────────    │     │  ───────────    │     │  ───────────    │       │
│  │  • Blocklists   │────▶│  • Categories   │────▶│  • Auto-block   │       │
│  │  • GeoIP        │     │  • Age decay    │     │  • Rate limit   │       │
│  │  • Abuse feeds  │     │  • Confidence   │     │  • Logging      │       │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘       │
│                                                                              │
│  Data Sources:                                                               │
│  ─────────────                                                              │
│  • AbuseIPDB, Spamhaus, Emerging Threats                                    │
│  • Custom blocklists, internal threat intel                                  │
│  • GeoIP databases for location-based rules                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## The Code

```rust
//! IP Reputation System with IPTables Integration
//!
//! Maintains an IP reputation database and provides automated
//! blocking via iptables for high-risk IPs.
//!
//! # Features
//! - Multiple threat feed sources
//! - Weighted scoring system
//! - Automatic iptables rule management
//! - IP whitelist support
//! - Time-based block expiration

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// COMMAND LINE INTERFACE
// ═══════════════════════════════════════════════════════════════════════════

/// IP Reputation Manager - Threat intelligence and iptables integration
#[derive(Parser, Debug)]
#[command(name = "ip-reputation")]
#[command(about = "Manage IP reputation and firewall rules")]
struct Args {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Check reputation of an IP address
    Check {
        /// IP address to check
        ip: String,
    },
    /// Block an IP address
    Block {
        /// IP address to block
        ip: String,
        /// Reason for blocking
        #[arg(short, long)]
        reason: Option<String>,
        /// Duration in hours (0 = permanent)
        #[arg(short, long, default_value = "24")]
        duration: u64,
    },
    /// Unblock an IP address
    Unblock {
        /// IP address to unblock
        ip: String,
    },
    /// Update threat feeds
    Update,
    /// List all blocked IPs
    List,
    /// Initialize iptables chains
    Init,
    /// Flush all IDS rules
    Flush,
    /// Import blocklist from file
    Import {
        /// Path to blocklist file
        file: String,
    },
    /// Export current blocklist
    Export {
        /// Output file path
        file: String,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// IP reputation entry
///
/// # Scoring System
/// Score ranges from 0-100:
/// - 0-30:   Low risk (normal traffic)
/// - 31-60:  Medium risk (monitor)
/// - 61-80:  High risk (consider blocking)
/// - 81-100: Critical (auto-block)
///
/// # Categories Explained
/// Different categories affect scoring:
/// - spam: Known spam source (+30)
/// - malware: Malware distribution (+50)
/// - botnet: Botnet C2 or node (+60)
/// - scanner: Port/vuln scanner (+20)
/// - tor: Tor exit node (+10)
/// - proxy: Anonymous proxy (+15)
/// - bruteforce: SSH/RDP bruteforce (+40)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    /// The IP address
    pub address: IpAddr,

    /// Reputation score (0-100, higher = worse)
    pub score: u32,

    /// Categories this IP belongs to
    pub categories: Vec<String>,

    /// When first seen
    pub first_seen: u64,

    /// When last updated
    pub last_updated: u64,

    /// Number of times reported
    pub report_count: u32,

    /// Confidence level (0-100)
    pub confidence: u32,

    /// Source of the intelligence
    pub sources: Vec<String>,

    /// Country code (if known)
    pub country: Option<String>,

    /// ASN (if known)
    pub asn: Option<u32>,
}

/// Block entry in iptables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    /// IP address
    pub address: IpAddr,

    /// Reason for block
    pub reason: String,

    /// When blocked
    pub blocked_at: u64,

    /// When to expire (0 = never)
    pub expires_at: u64,

    /// Rule ID for tracking
    pub rule_id: u32,

    /// Source (manual, auto, feed)
    pub source: BlockSource,
}

/// Source of the block decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockSource {
    /// Manually blocked by admin
    Manual,
    /// Auto-blocked by IDS
    Automatic,
    /// From threat feed
    ThreatFeed(String),
}

/// Threat feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    /// Feed name
    pub name: String,

    /// Feed URL
    pub url: String,

    /// Feed type (list, csv, json)
    pub format: FeedFormat,

    /// Category to assign
    pub category: String,

    /// Weight (multiplier for scoring)
    pub weight: f32,

    /// How often to update (seconds)
    pub update_interval: u64,

    /// Last update time
    pub last_update: u64,

    /// Is feed enabled
    pub enabled: bool,
}

/// Feed format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedFormat {
    /// One IP per line
    PlainList,
    /// CSV with IP in first column
    Csv,
    /// JSON array of IPs
    Json,
    /// STIX/TAXII format
    Stix,
}

/// Category weights for scoring
const CATEGORY_WEIGHTS: &[(&str, u32)] = &[
    ("malware", 50),
    ("botnet", 60),
    ("ransomware", 70),
    ("bruteforce", 40),
    ("spam", 30),
    ("phishing", 45),
    ("scanner", 20),
    ("tor", 10),
    ("proxy", 15),
    ("vpn", 5),
    ("ddos", 55),
];

// ═══════════════════════════════════════════════════════════════════════════
// IP REPUTATION DATABASE
// ═══════════════════════════════════════════════════════════════════════════

/// IP Reputation Database
///
/// # Architecture
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                    ReputationDatabase                            │
/// │                                                                  │
/// │  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
/// │  │   IP Entries     │  │   Whitelist      │  │  Threat Feeds │ │
/// │  │  HashMap<IP,Rep> │  │  HashSet<IP>     │  │  Vec<Feed>    │ │
/// │  └──────────────────┘  └──────────────────┘  └───────────────┘ │
/// │                                                                  │
/// │  Methods:                                                        │
/// │  • check_ip()     - Get reputation score                        │
/// │  • add_report()   - Add threat report                           │
/// │  • update_feeds() - Refresh threat data                         │
/// │  • calculate_score() - Compute weighted score                   │
/// └─────────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct ReputationDatabase {
    /// IP reputation entries
    entries: HashMap<IpAddr, IpReputation>,

    /// Whitelisted IPs (never block)
    whitelist: HashSet<IpAddr>,

    /// Configured threat feeds
    feeds: Vec<ThreatFeed>,

    /// Auto-block threshold
    block_threshold: u32,

    /// Database file path
    #[serde(skip)]
    db_path: String,
}

impl ReputationDatabase {
    /// Creates a new reputation database
    pub fn new(db_path: &str) -> Self {
        ReputationDatabase {
            entries: HashMap::new(),
            whitelist: HashSet::new(),
            feeds: Self::default_feeds(),
            block_threshold: 75,
            db_path: db_path.to_string(),
        }
    }

    /// Loads database from file
    pub fn load(path: &str) -> Result<Self, String> {
        if Path::new(path).exists() {
            let data = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read database: {}", e))?;
            let mut db: ReputationDatabase = serde_json::from_str(&data)
                .map_err(|e| format!("Failed to parse database: {}", e))?;
            db.db_path = path.to_string();
            Ok(db)
        } else {
            let mut db = Self::new(path);
            db.save()?;
            Ok(db)
        }
    }

    /// Saves database to file
    pub fn save(&self) -> Result<(), String> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize database: {}", e))?;
        fs::write(&self.db_path, data)
            .map_err(|e| format!("Failed to write database: {}", e))?;
        Ok(())
    }

    /// Default threat feeds
    fn default_feeds() -> Vec<ThreatFeed> {
        vec![
            ThreatFeed {
                name: "Emerging Threats - Compromised IPs".to_string(),
                url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
                format: FeedFormat::PlainList,
                category: "compromised".to_string(),
                weight: 1.0,
                update_interval: 3600,
                last_update: 0,
                enabled: true,
            },
            ThreatFeed {
                name: "Spamhaus DROP".to_string(),
                url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                format: FeedFormat::PlainList,
                category: "spam".to_string(),
                weight: 1.2,
                update_interval: 86400,
                last_update: 0,
                enabled: true,
            },
            ThreatFeed {
                name: "Feodo Tracker".to_string(),
                url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                format: FeedFormat::PlainList,
                category: "botnet".to_string(),
                weight: 1.5,
                update_interval: 3600,
                last_update: 0,
                enabled: true,
            },
        ]
    }

    /// Checks reputation of an IP
    ///
    /// # Returns
    /// - Score (0-100)
    /// - Categories
    /// - Should block (based on threshold)
    pub fn check_ip(&self, ip: &IpAddr) -> (u32, Vec<String>, bool) {
        // Whitelisted IPs always pass
        if self.whitelist.contains(ip) {
            return (0, vec!["whitelisted".to_string()], false);
        }

        if let Some(entry) = self.entries.get(ip) {
            let should_block = entry.score >= self.block_threshold;
            (entry.score, entry.categories.clone(), should_block)
        } else {
            (0, vec![], false)
        }
    }

    /// Adds or updates an IP entry
    pub fn add_entry(&mut self, ip: IpAddr, category: &str, source: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = self.entries.entry(ip).or_insert_with(|| {
            IpReputation {
                address: ip,
                score: 0,
                categories: vec![],
                first_seen: now,
                last_updated: now,
                report_count: 0,
                confidence: 50,
                sources: vec![],
                country: None,
                asn: None,
            }
        });

        // Add category if not present
        if !entry.categories.contains(&category.to_string()) {
            entry.categories.push(category.to_string());
        }

        // Add source if not present
        if !entry.sources.contains(&source.to_string()) {
            entry.sources.push(source.to_string());
        }

        entry.last_updated = now;
        entry.report_count += 1;

        // Recalculate score
        entry.score = self.calculate_score(&entry.categories, entry.report_count);
    }

    /// Calculates weighted score from categories
    fn calculate_score(&self, categories: &[String], report_count: u32) -> u32 {
        let mut score: u32 = 0;

        for category in categories {
            for (cat, weight) in CATEGORY_WEIGHTS {
                if category.to_lowercase().contains(cat) {
                    score += weight;
                }
            }
        }

        // Add points for multiple reports (max +20)
        score += (report_count.min(10) * 2) as u32;

        // Cap at 100
        score.min(100)
    }

    /// Adds IP to whitelist
    pub fn whitelist(&mut self, ip: IpAddr) {
        self.whitelist.insert(ip);
    }

    /// Removes IP from whitelist
    pub fn unwhitelist(&mut self, ip: &IpAddr) {
        self.whitelist.remove(ip);
    }

    /// Gets all IPs above threshold
    pub fn get_high_risk_ips(&self) -> Vec<&IpReputation> {
        self.entries
            .values()
            .filter(|e| e.score >= self.block_threshold)
            .collect()
    }

    /// Removes stale entries (not updated in X days)
    pub fn cleanup(&mut self, max_age_days: u64) {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() - (max_age_days * 86400);

        self.entries.retain(|_, e| e.last_updated > cutoff);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IPTABLES MANAGER
// ═══════════════════════════════════════════════════════════════════════════

/// Manages iptables rules for IP blocking
///
/// # Chain Structure
/// ```text
/// INPUT chain
///    └─► IDS_INPUT (our rules)
///         ├─► ACCEPT (whitelisted IPs)
///         ├─► DROP (blocked IPs)
///         └─► RETURN (pass to other rules)
///
/// OUTPUT chain (optional)
///    └─► IDS_OUTPUT
///
/// FORWARD chain (for gateways)
///    └─► IDS_FORWARD
/// ```
///
/// # Safety Features
/// - Maximum block limit (prevent resource exhaustion)
/// - Whitelist always checked first
/// - Automatic expiration of blocks
/// - Logging before drop for forensics
pub struct IptablesManager {
    /// Chain name for input rules
    chain_input: String,

    /// Chain name for output rules
    chain_output: String,

    /// Maximum number of blocks
    max_blocks: usize,

    /// Currently blocked IPs
    blocked: HashMap<IpAddr, BlockEntry>,

    /// Next rule ID
    next_rule_id: u32,

    /// Log prefix for iptables logging
    log_prefix: String,

    /// Enable logging before drop
    enable_logging: bool,

    /// State file path
    state_file: String,
}

impl IptablesManager {
    /// Creates a new iptables manager
    pub fn new(state_file: &str) -> Self {
        IptablesManager {
            chain_input: "IDS_BLOCK".to_string(),
            chain_output: "IDS_BLOCK_OUT".to_string(),
            max_blocks: 10000,
            blocked: HashMap::new(),
            next_rule_id: 1,
            log_prefix: "[IDS-BLOCK] ".to_string(),
            enable_logging: true,
            state_file: state_file.to_string(),
        }
    }

    /// Loads state from file
    pub fn load_state(&mut self) -> Result<(), String> {
        if Path::new(&self.state_file).exists() {
            let data = fs::read_to_string(&self.state_file)
                .map_err(|e| format!("Failed to read state: {}", e))?;
            self.blocked = serde_json::from_str(&data)
                .map_err(|e| format!("Failed to parse state: {}", e))?;

            // Find max rule ID
            self.next_rule_id = self.blocked
                .values()
                .map(|b| b.rule_id)
                .max()
                .unwrap_or(0) + 1;
        }
        Ok(())
    }

    /// Saves state to file
    pub fn save_state(&self) -> Result<(), String> {
        let data = serde_json::to_string_pretty(&self.blocked)
            .map_err(|e| format!("Failed to serialize state: {}", e))?;
        fs::write(&self.state_file, data)
            .map_err(|e| format!("Failed to write state: {}", e))?;
        Ok(())
    }

    /// Initializes iptables chains
    ///
    /// # Commands Executed
    /// ```bash
    /// # Create chains
    /// iptables -N IDS_BLOCK
    ///
    /// # Insert jump rules at top of INPUT/OUTPUT
    /// iptables -I INPUT 1 -j IDS_BLOCK
    ///
    /// # Add return rule at end
    /// iptables -A IDS_BLOCK -j RETURN
    /// ```
    pub fn initialize(&self) -> Result<(), String> {
        // Check for root/capabilities
        if !self.has_capability() {
            return Err("Requires root or CAP_NET_ADMIN capability".to_string());
        }

        // Create INPUT chain
        self.run_iptables(&["-N", &self.chain_input])?;

        // Insert jump to our chain (position 1 = top)
        // Ignore errors if already exists
        let _ = self.run_iptables(&["-D", "INPUT", "-j", &self.chain_input]);
        self.run_iptables(&["-I", "INPUT", "1", "-j", &self.chain_input])?;

        // Add return rule at end of our chain
        self.run_iptables(&["-A", &self.chain_input, "-j", "RETURN"])?;

        println!("[+] Initialized iptables chain: {}", self.chain_input);
        Ok(())
    }

    /// Checks if we have the required capability
    fn has_capability(&self) -> bool {
        // Try a harmless iptables command
        Command::new("iptables")
            .args(["-L", "-n"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Runs an iptables command
    fn run_iptables(&self, args: &[&str]) -> Result<(), String> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "chain already exists" errors
            if stderr.contains("Chain already exists") {
                Ok(())
            } else {
                Err(stderr.to_string())
            }
        }
    }

    /// Blocks an IP address
    ///
    /// # Rule Structure
    /// ```bash
    /// # With logging
    /// iptables -I IDS_BLOCK 1 -s 1.2.3.4 -j LOG --log-prefix "[IDS-BLOCK] "
    /// iptables -I IDS_BLOCK 2 -s 1.2.3.4 -j DROP
    ///
    /// # Without logging
    /// iptables -I IDS_BLOCK 1 -s 1.2.3.4 -j DROP
    /// ```
    pub fn block_ip(
        &mut self,
        ip: IpAddr,
        reason: &str,
        duration_hours: u64,
        source: BlockSource,
    ) -> Result<(), String> {
        // Check if already blocked
        if self.blocked.contains_key(&ip) {
            return Ok(()); // Already blocked
        }

        // Check limit
        if self.blocked.len() >= self.max_blocks {
            return Err("Maximum block limit reached".to_string());
        }

        let ip_str = ip.to_string();

        // Add logging rule first (if enabled)
        if self.enable_logging {
            self.run_iptables(&[
                "-I", &self.chain_input, "1",
                "-s", &ip_str,
                "-j", "LOG",
                "--log-prefix", &self.log_prefix,
            ])?;
        }

        // Add DROP rule
        let position = if self.enable_logging { "2" } else { "1" };
        self.run_iptables(&[
            "-I", &self.chain_input, position,
            "-s", &ip_str,
            "-j", "DROP",
        ])?;

        // Calculate expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = if duration_hours > 0 {
            now + (duration_hours * 3600)
        } else {
            0 // Never expires
        };

        // Record block
        let entry = BlockEntry {
            address: ip,
            reason: reason.to_string(),
            blocked_at: now,
            expires_at,
            rule_id: self.next_rule_id,
            source,
        };

        self.blocked.insert(ip, entry);
        self.next_rule_id += 1;

        self.save_state()?;
        println!("[+] Blocked IP: {} (reason: {})", ip, reason);

        Ok(())
    }

    /// Unblocks an IP address
    pub fn unblock_ip(&mut self, ip: &IpAddr) -> Result<(), String> {
        if !self.blocked.contains_key(ip) {
            return Ok(()); // Not blocked
        }

        let ip_str = ip.to_string();

        // Remove DROP rule
        self.run_iptables(&[
            "-D", &self.chain_input,
            "-s", &ip_str,
            "-j", "DROP",
        ])?;

        // Remove LOG rule if enabled
        if self.enable_logging {
            let _ = self.run_iptables(&[
                "-D", &self.chain_input,
                "-s", &ip_str,
                "-j", "LOG",
                "--log-prefix", &self.log_prefix,
            ]);
        }

        self.blocked.remove(ip);
        self.save_state()?;

        println!("[-] Unblocked IP: {}", ip);
        Ok(())
    }

    /// Processes expired blocks
    pub fn process_expirations(&mut self) -> Result<Vec<IpAddr>, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Find expired entries
        let expired: Vec<IpAddr> = self.blocked
            .iter()
            .filter(|(_, e)| e.expires_at > 0 && e.expires_at <= now)
            .map(|(ip, _)| *ip)
            .collect();

        // Unblock expired IPs
        for ip in &expired {
            self.unblock_ip(ip)?;
        }

        Ok(expired)
    }

    /// Lists all blocked IPs
    pub fn list_blocked(&self) -> Vec<&BlockEntry> {
        self.blocked.values().collect()
    }

    /// Flushes all IDS rules
    pub fn flush(&mut self) -> Result<(), String> {
        // Flush our chain
        self.run_iptables(&["-F", &self.chain_input])?;

        // Add return rule back
        self.run_iptables(&["-A", &self.chain_input, "-j", "RETURN"])?;

        self.blocked.clear();
        self.save_state()?;

        println!("[*] Flushed all IDS rules");
        Ok(())
    }

    /// Gets iptables statistics for our chain
    pub fn get_stats(&self) -> Result<String, String> {
        let output = Command::new("iptables")
            .args(["-L", &self.chain_input, "-v", "-n"])
            .output()
            .map_err(|e| format!("Failed to get stats: {}", e))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAT FEED UPDATER
// ═══════════════════════════════════════════════════════════════════════════

/// Updates threat feeds and imports IPs
pub struct FeedUpdater {
    /// HTTP client
    client: reqwest::blocking::Client,
}

impl FeedUpdater {
    pub fn new() -> Self {
        FeedUpdater {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Updates a single feed
    pub fn update_feed(
        &self,
        feed: &ThreatFeed,
        db: &mut ReputationDatabase,
    ) -> Result<usize, String> {
        println!("[*] Updating feed: {}", feed.name);

        let response = self.client
            .get(&feed.url)
            .send()
            .map_err(|e| format!("Failed to fetch feed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        let content = response.text()
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let ips = self.parse_feed(&content, &feed.format)?;
        let count = ips.len();

        for ip in ips {
            db.add_entry(ip, &feed.category, &feed.name);
        }

        println!("[+] Imported {} IPs from {}", count, feed.name);
        Ok(count)
    }

    /// Parses feed content based on format
    fn parse_feed(&self, content: &str, format: &FeedFormat) -> Result<Vec<IpAddr>, String> {
        match format {
            FeedFormat::PlainList => {
                Ok(content.lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .filter_map(|line| {
                        // Handle CIDR notation (just take first IP for now)
                        let ip_str = line.split('/').next()?;
                        let ip_str = ip_str.split_whitespace().next()?;
                        ip_str.trim().parse().ok()
                    })
                    .collect())
            }
            FeedFormat::Csv => {
                Ok(content.lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .filter_map(|line| {
                        let first_col = line.split(',').next()?;
                        first_col.trim().parse().ok()
                    })
                    .collect())
            }
            FeedFormat::Json => {
                let ips: Vec<String> = serde_json::from_str(content)
                    .map_err(|e| format!("JSON parse error: {}", e))?;
                Ok(ips.iter()
                    .filter_map(|s| s.parse().ok())
                    .collect())
            }
            FeedFormat::Stix => {
                Err("STIX format not yet implemented".to_string())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║          IP REPUTATION & IPTABLES MANAGER                       ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    let db_path = "/var/lib/ids/reputation.json";
    let state_path = "/var/lib/ids/iptables_state.json";

    // Ensure directory exists
    if let Some(parent) = Path::new(db_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut db = ReputationDatabase::load(db_path)
        .unwrap_or_else(|e| {
            eprintln!("[!] Warning: {}", e);
            ReputationDatabase::new(db_path)
        });

    let mut ipt = IptablesManager::new(state_path);
    let _ = ipt.load_state();

    match args.command {
        Commands::Check { ip } => {
            let ip: IpAddr = ip.parse()
                .expect("Invalid IP address");

            let (score, categories, should_block) = db.check_ip(&ip);

            println!("[*] IP: {}", ip);
            println!("    Score: {}/100", score);
            println!("    Categories: {:?}", categories);
            println!("    Should Block: {}", should_block);

            if let Some(entry) = db.entries.get(&ip) {
                println!("    Reports: {}", entry.report_count);
                println!("    Sources: {:?}", entry.sources);
            }
        }

        Commands::Block { ip, reason, duration } => {
            let ip: IpAddr = ip.parse()
                .expect("Invalid IP address");

            let reason = reason.unwrap_or_else(|| "Manual block".to_string());

            match ipt.block_ip(ip, &reason, duration, BlockSource::Manual) {
                Ok(()) => println!("[+] Successfully blocked {}", ip),
                Err(e) => eprintln!("[-] Failed to block: {}", e),
            }
        }

        Commands::Unblock { ip } => {
            let ip: IpAddr = ip.parse()
                .expect("Invalid IP address");

            match ipt.unblock_ip(&ip) {
                Ok(()) => println!("[+] Successfully unblocked {}", ip),
                Err(e) => eprintln!("[-] Failed to unblock: {}", e),
            }
        }

        Commands::Update => {
            let updater = FeedUpdater::new();

            for feed in &db.feeds.clone() {
                if feed.enabled {
                    match updater.update_feed(feed, &mut db) {
                        Ok(count) => {
                            println!("[+] Updated {}: {} IPs", feed.name, count);
                        }
                        Err(e) => {
                            eprintln!("[-] Failed to update {}: {}", feed.name, e);
                        }
                    }
                }
            }

            if let Err(e) = db.save() {
                eprintln!("[-] Failed to save database: {}", e);
            }
        }

        Commands::List => {
            let blocked = ipt.list_blocked();

            if blocked.is_empty() {
                println!("[*] No IPs currently blocked");
            } else {
                println!("[*] Blocked IPs ({} total):", blocked.len());
                for entry in blocked {
                    let expires = if entry.expires_at > 0 {
                        format!("expires: {}", entry.expires_at)
                    } else {
                        "permanent".to_string()
                    };
                    println!("    {} - {} ({})", entry.address, entry.reason, expires);
                }
            }
        }

        Commands::Init => {
            match ipt.initialize() {
                Ok(()) => println!("[+] IPTables initialized successfully"),
                Err(e) => eprintln!("[-] Failed to initialize: {}", e),
            }
        }

        Commands::Flush => {
            match ipt.flush() {
                Ok(()) => println!("[+] All rules flushed"),
                Err(e) => eprintln!("[-] Failed to flush: {}", e),
            }
        }

        Commands::Import { file } => {
            match fs::read_to_string(&file) {
                Ok(content) => {
                    let mut count = 0;
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }

                        if let Ok(ip) = line.parse::<IpAddr>() {
                            db.add_entry(ip, "imported", &file);
                            count += 1;
                        }
                    }
                    println!("[+] Imported {} IPs from {}", count, file);

                    if let Err(e) = db.save() {
                        eprintln!("[-] Failed to save database: {}", e);
                    }
                }
                Err(e) => eprintln!("[-] Failed to read file: {}", e),
            }
        }

        Commands::Export { file } => {
            let high_risk: Vec<String> = db.get_high_risk_ips()
                .iter()
                .map(|e| e.address.to_string())
                .collect();

            match fs::write(&file, high_risk.join("\n")) {
                Ok(()) => println!("[+] Exported {} IPs to {}", high_risk.len(), file),
                Err(e) => eprintln!("[-] Failed to write file: {}", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_score_calculation() {
        let db = ReputationDatabase::new("/tmp/test.json");

        // Single category
        let score = db.calculate_score(&["malware".to_string()], 1);
        assert!(score >= 50);

        // Multiple categories
        let score = db.calculate_score(
            &["malware".to_string(), "botnet".to_string()],
            1
        );
        assert!(score >= 100); // Would be 110 but capped at 100
    }

    #[test]
    fn test_whitelist() {
        let mut db = ReputationDatabase::new("/tmp/test.json");
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Add to whitelist
        db.whitelist(ip);

        // Add a malicious entry
        db.add_entry(ip, "malware", "test");

        // Should still be clean due to whitelist
        let (score, categories, should_block) = db.check_ip(&ip);
        assert_eq!(score, 0);
        assert!(categories.contains(&"whitelisted".to_string()));
        assert!(!should_block);
    }
}
```

## Line-by-Line Breakdown

### IPTables Chain Creation

```rust
self.run_iptables(&["-N", &self.chain_input])?;
self.run_iptables(&["-I", "INPUT", "1", "-j", &self.chain_input])?;
self.run_iptables(&["-A", &self.chain_input, "-j", "RETURN"])?;
```

**Line-by-Line:**
1. `-N IDS_BLOCK` - Creates a new chain named IDS_BLOCK
2. `-I INPUT 1 -j IDS_BLOCK` - Inserts a jump to our chain at position 1 (top)
3. `-A IDS_BLOCK -j RETURN` - Appends RETURN at end (pass to next chain)

### Blocking an IP

```rust
// Add LOG rule
self.run_iptables(&[
    "-I", &self.chain_input, "1",
    "-s", &ip_str,
    "-j", "LOG",
    "--log-prefix", &self.log_prefix,
])?;

// Add DROP rule
self.run_iptables(&[
    "-I", &self.chain_input, "2",
    "-s", &ip_str,
    "-j", "DROP",
])?;
```

**Why Two Rules?**
1. LOG rule writes to syslog for forensics
2. DROP rule actually blocks the traffic
3. Order matters: LOG first, then DROP

## Red Team Perspective

### Evading IP Reputation
```
1. IP Rotation
   └─► Use cloud infrastructure with frequent IP changes

2. Residential Proxies
   └─► Route through clean residential IPs

3. Domain Fronting
   └─► Hide behind CDN/cloud provider IPs

4. Tor/VPN Chains
   └─► Multiple hops to obscure origin

5. Compromised Hosts
   └─► Use hacked systems as proxies
```

### Testing Evasion
- Check if your IP is on public blocklists
- Use Shodan to assess your infrastructure reputation
- Monitor for your IPs in threat intel feeds

## Blue Team Perspective

### Improving Detection
```
1. Multiple Feed Sources
   └─► Correlate across feeds for confidence

2. GeoIP Integration
   └─► Flag connections from unexpected countries

3. ASN Reputation
   └─► Track reputation at ASN level

4. Behavioral Scoring
   └─► Adjust reputation based on observed behavior

5. Decay Functions
   └─► Reduce score over time if no new reports
```

### Integration Points
- SIEM integration for correlation
- SOAR for automated response
- Threat intel platforms (MISP, OpenCTI)
- Cloud firewall APIs (AWS WAF, Cloudflare)

## Exercises

### Exercise 1: Add GeoIP Support
Integrate MaxMind GeoIP database to add country/ASN info to IP entries.

### Exercise 2: Add Rate Limiting
Instead of blocking, implement rate limiting using iptables `hashlimit`.

### Exercise 3: Add IPv6 Support
Extend the iptables manager to handle IPv6 using `ip6tables`.

### Exercise 4: Add Webhook Notifications
Send webhook to Slack/Discord when high-risk IP is detected.

### Exercise 5: Add CIDR Support
Handle network blocks (CIDR) in blocklists, not just individual IPs.

---

**← Previous:** [IDS02: Rule Engine](../02_Rule_Engine/README.md) | **Next →** [IDS04: Alert System](../04_Alert_System/README.md)
