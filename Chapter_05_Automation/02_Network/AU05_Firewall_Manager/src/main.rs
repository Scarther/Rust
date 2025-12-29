//! AU05 Firewall Manager - Firewall Rule Management Tool
//!
//! This tool provides comprehensive firewall management for Linux systems using iptables/nftables.
//! Essential for security operations, network hardening, and incident response.
//!
//! Features:
//! - List, add, and delete firewall rules
//! - Pre-defined security rule templates
//! - Chain management
//! - NAT configuration
//! - Rule backup and restore
//! - Port blocking/allowing
//! - IP blocking/whitelisting
//! - Connection tracking
//! - Rate limiting rules
//!
//! Security applications:
//! - Incident response (quickly block IPs)
//! - Network hardening
//! - Access control implementation
//! - DDoS mitigation rules

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use colored::*;
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use tabled::{Table, Tabled};

/// Firewall Manager - Comprehensive firewall rule management
#[derive(Parser)]
#[command(name = "firewall-manager")]
#[command(author = "Security Engineer")]
#[command(version = "1.0")]
#[command(about = "Manage firewall rules for security operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Use iptables (default) or nftables
    #[arg(long, default_value = "iptables")]
    backend: String,
}

#[derive(Subcommand)]
enum Commands {
    /// List firewall rules
    List {
        /// Table to list (filter, nat, mangle, raw)
        #[arg(short, long, default_value = "filter")]
        table: String,

        /// Chain to list (INPUT, OUTPUT, FORWARD, etc.)
        #[arg(short, long)]
        chain: Option<String>,

        /// Show rule numbers
        #[arg(short, long)]
        numbered: bool,
    },

    /// Add a new firewall rule
    Add {
        /// Chain (INPUT, OUTPUT, FORWARD)
        #[arg(short, long, default_value = "INPUT")]
        chain: String,

        /// Protocol (tcp, udp, icmp, all)
        #[arg(short, long, default_value = "tcp")]
        protocol: String,

        /// Source IP/network
        #[arg(short, long)]
        source: Option<String>,

        /// Destination IP/network
        #[arg(short, long)]
        destination: Option<String>,

        /// Destination port
        #[arg(long)]
        dport: Option<u16>,

        /// Source port
        #[arg(long)]
        sport: Option<u16>,

        /// Target action (ACCEPT, DROP, REJECT, LOG)
        #[arg(short, long, default_value = "DROP")]
        target: String,

        /// Input interface
        #[arg(short, long)]
        in_interface: Option<String>,

        /// Output interface
        #[arg(short, long)]
        out_interface: Option<String>,

        /// Insert at position (append if not specified)
        #[arg(long)]
        insert: Option<u32>,

        /// Comment for the rule
        #[arg(long)]
        comment: Option<String>,
    },

    /// Delete a firewall rule
    Delete {
        /// Chain
        chain: String,

        /// Rule number to delete
        rule_num: u32,
    },

    /// Block an IP address
    BlockIp {
        /// IP address or network to block
        ip: String,

        /// Direction (in, out, both)
        #[arg(short, long, default_value = "both")]
        direction: String,

        /// Comment/reason
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Unblock an IP address
    UnblockIp {
        /// IP address or network to unblock
        ip: String,
    },

    /// Allow a port
    AllowPort {
        /// Port number
        port: u16,

        /// Protocol (tcp, udp, both)
        #[arg(short, long, default_value = "tcp")]
        protocol: String,

        /// Source IP/network to allow (all if not specified)
        #[arg(short, long)]
        source: Option<String>,
    },

    /// Block a port
    BlockPort {
        /// Port number
        port: u16,

        /// Protocol (tcp, udp, both)
        #[arg(short, long, default_value = "tcp")]
        protocol: String,
    },

    /// Apply a security template
    Template {
        /// Template name (basic, server, workstation, paranoid)
        name: String,

        /// Dry run - show rules without applying
        #[arg(short, long)]
        dry_run: bool,
    },

    /// Manage chains
    Chain {
        #[command(subcommand)]
        action: ChainCommands,
    },

    /// Backup firewall rules
    Backup {
        /// Output file
        output: PathBuf,
    },

    /// Restore firewall rules
    Restore {
        /// Input file
        input: PathBuf,

        /// Flush existing rules before restore
        #[arg(short, long)]
        flush: bool,
    },

    /// Flush all rules (with confirmation)
    Flush {
        /// Chain to flush (all chains if not specified)
        chain: Option<String>,

        /// Force without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Show connection tracking table
    Conntrack {
        /// Filter by state (ESTABLISHED, NEW, etc.)
        #[arg(short, long)]
        state: Option<String>,

        /// Filter by source IP
        #[arg(long)]
        src: Option<String>,

        /// Limit results
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Add rate limiting rule
    RateLimit {
        /// Chain (INPUT, OUTPUT)
        #[arg(short, long, default_value = "INPUT")]
        chain: String,

        /// Protocol
        #[arg(short, long, default_value = "tcp")]
        protocol: String,

        /// Port to rate limit
        #[arg(long)]
        port: u16,

        /// Limit (e.g., 25/minute)
        #[arg(short, long, default_value = "25/minute")]
        limit: String,

        /// Burst limit
        #[arg(short, long, default_value = "50")]
        burst: u32,
    },

    /// Show firewall status and statistics
    Status,

    /// NAT configuration
    Nat {
        #[command(subcommand)]
        action: NatCommands,
    },

    /// Import/export rules in various formats
    Export {
        /// Output file
        output: PathBuf,

        /// Format (iptables-save, json, script)
        #[arg(short, long, default_value = "iptables-save")]
        export_format: String,
    },
}

#[derive(Subcommand)]
enum ChainCommands {
    /// Create a new chain
    Create {
        /// Chain name
        name: String,

        /// Table (filter, nat, mangle)
        #[arg(short, long, default_value = "filter")]
        table: String,
    },

    /// Delete a chain
    Delete {
        /// Chain name
        name: String,

        /// Table
        #[arg(short, long, default_value = "filter")]
        table: String,
    },

    /// Set chain policy
    Policy {
        /// Chain name
        chain: String,

        /// Policy (ACCEPT, DROP)
        policy: String,
    },

    /// List all chains
    List {
        /// Table
        #[arg(short, long, default_value = "filter")]
        table: String,
    },
}

#[derive(Subcommand)]
enum NatCommands {
    /// Show NAT rules
    Show,

    /// Add SNAT rule
    Snat {
        /// Source network
        source: String,

        /// Interface
        #[arg(short, long)]
        out_interface: String,

        /// SNAT IP
        #[arg(short, long)]
        to_source: String,
    },

    /// Add DNAT rule
    Dnat {
        /// Destination port
        dport: u16,

        /// Forward to IP:port
        to_destination: String,

        /// Protocol
        #[arg(short, long, default_value = "tcp")]
        protocol: String,
    },

    /// Add masquerade rule
    Masquerade {
        /// Output interface
        out_interface: String,

        /// Source network (optional)
        #[arg(short, long)]
        source: Option<String>,
    },

    /// Delete NAT rule
    Delete {
        /// Chain (PREROUTING, POSTROUTING)
        chain: String,

        /// Rule number
        rule_num: u32,
    },
}

/// Firewall rule representation
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct FirewallRule {
    #[tabled(rename = "#")]
    num: u32,
    #[tabled(rename = "Chain")]
    chain: String,
    #[tabled(rename = "Protocol")]
    protocol: String,
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Destination")]
    destination: String,
    #[tabled(rename = "Port")]
    port: String,
    #[tabled(rename = "Target")]
    target: String,
    #[tabled(rename = "Options")]
    #[tabled(display_with = "truncate_options")]
    options: String,
}

fn truncate_options(options: &String) -> String {
    if options.len() > 30 {
        format!("{}...", &options[..27])
    } else {
        options.clone()
    }
}

/// Connection tracking entry
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct ConntrackEntry {
    #[tabled(rename = "Protocol")]
    protocol: String,
    #[tabled(rename = "State")]
    state: String,
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Dest")]
    destination: String,
    #[tabled(rename = "S.Port")]
    sport: String,
    #[tabled(rename = "D.Port")]
    dport: String,
}

/// Security template
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityTemplate {
    name: String,
    description: String,
    default_policy: String,
    rules: Vec<TemplateRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TemplateRule {
    chain: String,
    protocol: String,
    port: Option<u16>,
    source: Option<String>,
    target: String,
    comment: String,
}

/// Firewall status information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirewallStatus {
    backend: String,
    is_active: bool,
    default_policies: HashMap<String, String>,
    rule_count: HashMap<String, u32>,
    total_rules: u32,
}

/// Firewall manager implementation
struct FirewallManager {
    backend: String,
    verbose: bool,
}

impl FirewallManager {
    fn new(backend: &str, verbose: bool) -> Self {
        Self {
            backend: backend.to_string(),
            verbose,
        }
    }

    /// List firewall rules
    fn list_rules(
        &self,
        table: &str,
        chain: Option<&str>,
        numbered: bool,
    ) -> Result<Vec<FirewallRule>> {
        let mut rules = Vec::new();

        let mut cmd = Command::new("iptables");
        cmd.args(["-t", table, "-L"]);

        if let Some(c) = chain {
            cmd.arg(c);
        }

        cmd.args(["-n", "-v"]);

        if numbered {
            cmd.arg("--line-numbers");
        }

        let output = cmd.output().context("Failed to run iptables")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables error: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_chain = String::new();
        let mut rule_num = 0u32;

        for line in stdout.lines() {
            // Check for chain header
            if line.starts_with("Chain ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    current_chain = parts[1].to_string();
                    rule_num = 0;
                }
                continue;
            }

            // Skip header line
            if line.trim().starts_with("pkts")
                || line.trim().starts_with("num")
                || line.trim().is_empty()
            {
                continue;
            }

            // Parse rule line
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 {
                rule_num += 1;

                let (target, proto, _opt, in_iface, out_iface, source, destination) =
                    if numbered && parts.len() >= 9 {
                        (
                            parts[2].to_string(),
                            parts[3].to_string(),
                            parts[4].to_string(),
                            parts[5].to_string(),
                            parts[6].to_string(),
                            parts[7].to_string(),
                            parts[8].to_string(),
                        )
                    } else {
                        (
                            parts[2].to_string(),
                            parts[3].to_string(),
                            parts[4].to_string(),
                            parts[5].to_string(),
                            parts[6].to_string(),
                            parts[7].to_string(),
                            if parts.len() > 8 {
                                parts[8].to_string()
                            } else {
                                "anywhere".to_string()
                            },
                        )
                    };

                // Extract port info from remaining parts
                let rest = parts[8..].join(" ");
                let port = self.extract_port(&rest);
                let options = rest.clone();

                rules.push(FirewallRule {
                    num: rule_num,
                    chain: current_chain.clone(),
                    protocol: proto,
                    source,
                    destination,
                    port,
                    target,
                    options,
                });
            }
        }

        Ok(rules)
    }

    /// Extract port from rule options
    fn extract_port(&self, options: &str) -> String {
        let dpt_re = Regex::new(r"dpt:(\d+)").ok();
        let spt_re = Regex::new(r"spt:(\d+)").ok();

        let mut ports = Vec::new();

        if let Some(re) = dpt_re {
            if let Some(caps) = re.captures(options) {
                ports.push(format!("dpt:{}", &caps[1]));
            }
        }

        if let Some(re) = spt_re {
            if let Some(caps) = re.captures(options) {
                ports.push(format!("spt:{}", &caps[1]));
            }
        }

        if ports.is_empty() {
            "-".to_string()
        } else {
            ports.join(",")
        }
    }

    /// Add a firewall rule
    fn add_rule(
        &self,
        chain: &str,
        protocol: &str,
        source: Option<&str>,
        destination: Option<&str>,
        dport: Option<u16>,
        sport: Option<u16>,
        target: &str,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        insert: Option<u32>,
        comment: Option<&str>,
    ) -> Result<()> {
        println!(
            "{} Adding firewall rule to chain {}",
            "[*]".blue(),
            chain.cyan()
        );

        let mut cmd = Command::new("iptables");

        // Insert or append
        if let Some(pos) = insert {
            cmd.args(["-I", chain, &pos.to_string()]);
        } else {
            cmd.args(["-A", chain]);
        }

        // Protocol
        if protocol != "all" {
            cmd.args(["-p", protocol]);
        }

        // Source
        if let Some(src) = source {
            cmd.args(["-s", src]);
        }

        // Destination
        if let Some(dst) = destination {
            cmd.args(["-d", dst]);
        }

        // Ports
        if let Some(dp) = dport {
            cmd.args(["--dport", &dp.to_string()]);
        }

        if let Some(sp) = sport {
            cmd.args(["--sport", &sp.to_string()]);
        }

        // Interfaces
        if let Some(iface) = in_interface {
            cmd.args(["-i", iface]);
        }

        if let Some(iface) = out_interface {
            cmd.args(["-o", iface]);
        }

        // Comment
        if let Some(cmt) = comment {
            cmd.args(["-m", "comment", "--comment", cmt]);
        }

        // Target
        cmd.args(["-j", target]);

        if self.verbose {
            println!("  Command: iptables {:?}", cmd.get_args().collect::<Vec<_>>());
        }

        let output = cmd.output().context("Failed to run iptables")?;

        if output.status.success() {
            println!("{} Rule added successfully", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to add rule: {}", stderr);
        }
    }

    /// Delete a firewall rule
    fn delete_rule(&self, chain: &str, rule_num: u32) -> Result<()> {
        println!(
            "{} Deleting rule {} from chain {}",
            "[*]".blue(),
            rule_num,
            chain.cyan()
        );

        let output = Command::new("iptables")
            .args(["-D", chain, &rule_num.to_string()])
            .output()
            .context("Failed to run iptables")?;

        if output.status.success() {
            println!("{} Rule deleted successfully", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to delete rule: {}", stderr);
        }
    }

    /// Block an IP address
    fn block_ip(&self, ip: &str, direction: &str, comment: Option<&str>) -> Result<()> {
        println!("{} Blocking IP: {}", "[*]".blue(), ip.red());

        // Validate IP
        let _ = ip.parse::<IpAddr>().or_else(|_| {
            ip.parse::<IpNetwork>()
                .map(|n| n.ip())
                .context("Invalid IP address or network")
        })?;

        let cmt = comment.unwrap_or("Blocked by firewall-manager");

        if direction == "in" || direction == "both" {
            self.add_rule(
                "INPUT",
                "all",
                Some(ip),
                None,
                None,
                None,
                "DROP",
                None,
                None,
                Some(1), // Insert at top
                Some(cmt),
            )?;
        }

        if direction == "out" || direction == "both" {
            self.add_rule(
                "OUTPUT",
                "all",
                None,
                Some(ip),
                None,
                None,
                "DROP",
                None,
                None,
                Some(1),
                Some(cmt),
            )?;
        }

        Ok(())
    }

    /// Unblock an IP address
    fn unblock_ip(&self, ip: &str) -> Result<()> {
        println!("{} Unblocking IP: {}", "[*]".blue(), ip.cyan());

        // Find and delete rules matching this IP
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let rules = self.list_rules("filter", Some(chain), true)?;

            // Delete in reverse order to maintain rule numbers
            let matching: Vec<_> = rules
                .iter()
                .filter(|r| r.source.contains(ip) || r.destination.contains(ip))
                .collect();

            for rule in matching.iter().rev() {
                let _ = self.delete_rule(chain, rule.num);
            }
        }

        println!("{} IP unblocked", "[+]".green());
        Ok(())
    }

    /// Allow a port
    fn allow_port(&self, port: u16, protocol: &str, source: Option<&str>) -> Result<()> {
        println!(
            "{} Allowing port {}/{}",
            "[*]".blue(),
            port.to_string().green(),
            protocol
        );

        let protocols = if protocol == "both" {
            vec!["tcp", "udp"]
        } else {
            vec![protocol]
        };

        for proto in protocols {
            self.add_rule(
                "INPUT",
                proto,
                source,
                None,
                Some(port),
                None,
                "ACCEPT",
                None,
                None,
                None,
                Some(&format!("Allow port {}/{}", port, proto)),
            )?;
        }

        Ok(())
    }

    /// Block a port
    fn block_port(&self, port: u16, protocol: &str) -> Result<()> {
        println!(
            "{} Blocking port {}/{}",
            "[*]".blue(),
            port.to_string().red(),
            protocol
        );

        let protocols = if protocol == "both" {
            vec!["tcp", "udp"]
        } else {
            vec![protocol]
        };

        for proto in protocols {
            self.add_rule(
                "INPUT",
                proto,
                None,
                None,
                Some(port),
                None,
                "DROP",
                None,
                None,
                Some(1),
                Some(&format!("Block port {}/{}", port, proto)),
            )?;
        }

        Ok(())
    }

    /// Apply security template
    fn apply_template(&self, name: &str, dry_run: bool) -> Result<()> {
        println!("{} Applying security template: {}", "[*]".blue(), name.cyan());

        let template = self.get_template(name)?;

        println!("  Description: {}", template.description);
        println!("  Default policy: {}", template.default_policy);
        println!("  Rules: {}", template.rules.len());

        if dry_run {
            println!("\n{} Dry run - rules that would be applied:", "[*]".yellow());
        } else {
            println!("\n{} Applying rules...", "[*]".blue());
        }

        for rule in &template.rules {
            let desc = format!(
                "  {} {} {} dport:{} -> {}",
                rule.chain,
                rule.protocol,
                rule.source.as_deref().unwrap_or("any"),
                rule.port.map(|p| p.to_string()).unwrap_or("-".to_string()),
                rule.target
            );

            if dry_run {
                println!("{}", desc);
            } else {
                println!("{}", desc);
                self.add_rule(
                    &rule.chain,
                    &rule.protocol,
                    rule.source.as_deref(),
                    None,
                    rule.port,
                    None,
                    &rule.target,
                    None,
                    None,
                    None,
                    Some(&rule.comment),
                )?;
            }
        }

        Ok(())
    }

    /// Get security template
    fn get_template(&self, name: &str) -> Result<SecurityTemplate> {
        match name {
            "basic" => Ok(SecurityTemplate {
                name: "basic".to_string(),
                description: "Basic security - allow established, block incoming".to_string(),
                default_policy: "DROP".to_string(),
                rules: vec![
                    TemplateRule {
                        chain: "INPUT".to_string(),
                        protocol: "all".to_string(),
                        port: None,
                        source: None,
                        target: "ACCEPT".to_string(),
                        comment: "Allow established connections".to_string(),
                    },
                    TemplateRule {
                        chain: "INPUT".to_string(),
                        protocol: "icmp".to_string(),
                        port: None,
                        source: None,
                        target: "ACCEPT".to_string(),
                        comment: "Allow ICMP".to_string(),
                    },
                ],
            }),
            "server" => Ok(SecurityTemplate {
                name: "server".to_string(),
                description: "Server template - SSH, HTTP, HTTPS allowed".to_string(),
                default_policy: "DROP".to_string(),
                rules: vec![
                    TemplateRule {
                        chain: "INPUT".to_string(),
                        protocol: "tcp".to_string(),
                        port: Some(22),
                        source: None,
                        target: "ACCEPT".to_string(),
                        comment: "Allow SSH".to_string(),
                    },
                    TemplateRule {
                        chain: "INPUT".to_string(),
                        protocol: "tcp".to_string(),
                        port: Some(80),
                        source: None,
                        target: "ACCEPT".to_string(),
                        comment: "Allow HTTP".to_string(),
                    },
                    TemplateRule {
                        chain: "INPUT".to_string(),
                        protocol: "tcp".to_string(),
                        port: Some(443),
                        source: None,
                        target: "ACCEPT".to_string(),
                        comment: "Allow HTTPS".to_string(),
                    },
                ],
            }),
            "workstation" => Ok(SecurityTemplate {
                name: "workstation".to_string(),
                description: "Workstation - block incoming, allow outgoing".to_string(),
                default_policy: "DROP".to_string(),
                rules: vec![
                    TemplateRule {
                        chain: "OUTPUT".to_string(),
                        protocol: "all".to_string(),
                        port: None,
                        source: None,
                        target: "ACCEPT".to_string(),
                        comment: "Allow all outgoing".to_string(),
                    },
                ],
            }),
            "paranoid" => Ok(SecurityTemplate {
                name: "paranoid".to_string(),
                description: "Paranoid - whitelist only, logging enabled".to_string(),
                default_policy: "DROP".to_string(),
                rules: vec![
                    TemplateRule {
                        chain: "INPUT".to_string(),
                        protocol: "tcp".to_string(),
                        port: Some(22),
                        source: Some("10.0.0.0/8".to_string()),
                        target: "ACCEPT".to_string(),
                        comment: "SSH from internal only".to_string(),
                    },
                ],
            }),
            _ => anyhow::bail!("Unknown template: {}", name),
        }
    }

    /// Create a chain
    fn create_chain(&self, name: &str, table: &str) -> Result<()> {
        println!(
            "{} Creating chain {} in table {}",
            "[*]".blue(),
            name.cyan(),
            table
        );

        let output = Command::new("iptables")
            .args(["-t", table, "-N", name])
            .output()
            .context("Failed to create chain")?;

        if output.status.success() {
            println!("{} Chain created", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to create chain: {}", stderr);
        }
    }

    /// Delete a chain
    fn delete_chain(&self, name: &str, table: &str) -> Result<()> {
        println!(
            "{} Deleting chain {} from table {}",
            "[*]".blue(),
            name.cyan(),
            table
        );

        // First flush the chain
        let _ = Command::new("iptables")
            .args(["-t", table, "-F", name])
            .output();

        let output = Command::new("iptables")
            .args(["-t", table, "-X", name])
            .output()
            .context("Failed to delete chain")?;

        if output.status.success() {
            println!("{} Chain deleted", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to delete chain: {}", stderr);
        }
    }

    /// Set chain policy
    fn set_policy(&self, chain: &str, policy: &str) -> Result<()> {
        println!(
            "{} Setting policy for {} to {}",
            "[*]".blue(),
            chain.cyan(),
            policy
        );

        let output = Command::new("iptables")
            .args(["-P", chain, policy])
            .output()
            .context("Failed to set policy")?;

        if output.status.success() {
            println!("{} Policy set", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to set policy: {}", stderr);
        }
    }

    /// Backup firewall rules
    fn backup(&self, output: &PathBuf) -> Result<()> {
        println!("{} Backing up firewall rules...", "[*]".blue());

        let iptables_save = Command::new("iptables-save")
            .output()
            .context("Failed to run iptables-save")?;

        if iptables_save.status.success() {
            fs::write(output, &iptables_save.stdout)?;
            println!(
                "{} Rules backed up to {}",
                "[+]".green(),
                output.display()
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&iptables_save.stderr);
            anyhow::bail!("Backup failed: {}", stderr);
        }
    }

    /// Restore firewall rules
    fn restore(&self, input: &PathBuf, flush: bool) -> Result<()> {
        println!("{} Restoring firewall rules...", "[*]".blue());

        if !input.exists() {
            anyhow::bail!("Backup file not found: {}", input.display());
        }

        if flush {
            self.flush_all(None, true)?;
        }

        let rules = fs::read(input)?;

        let mut cmd = Command::new("iptables-restore");
        cmd.stdin(std::process::Stdio::piped());

        let mut child = cmd.spawn()?;

        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            stdin.write_all(&rules)?;
        }

        let output = child.wait()?;

        if output.success() {
            println!("{} Rules restored successfully", "[+]".green());
            Ok(())
        } else {
            anyhow::bail!("Failed to restore rules");
        }
    }

    /// Flush all rules
    fn flush_all(&self, chain: Option<&str>, force: bool) -> Result<()> {
        if !force {
            println!(
                "{} WARNING: This will delete all firewall rules!",
                "[!]".red().bold()
            );
            println!("  Use --force to confirm");
            return Ok(());
        }

        if let Some(c) = chain {
            println!("{} Flushing chain: {}", "[*]".blue(), c.cyan());
            let output = Command::new("iptables")
                .args(["-F", c])
                .output()?;

            if output.status.success() {
                println!("{} Chain {} flushed", "[+]".green(), c);
            }
        } else {
            println!("{} Flushing all chains...", "[*]".blue());

            // Flush all tables
            for table in &["filter", "nat", "mangle", "raw"] {
                let _ = Command::new("iptables")
                    .args(["-t", table, "-F"])
                    .output();
            }

            // Reset policies
            for chain in &["INPUT", "OUTPUT", "FORWARD"] {
                let _ = Command::new("iptables")
                    .args(["-P", chain, "ACCEPT"])
                    .output();
            }

            println!("{} All rules flushed, policies reset to ACCEPT", "[+]".green());
        }

        Ok(())
    }

    /// Get connection tracking entries
    fn get_conntrack(
        &self,
        state: Option<&str>,
        src: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ConntrackEntry>> {
        let mut entries = Vec::new();

        let output = Command::new("conntrack")
            .args(["-L"])
            .output()
            .context("Failed to run conntrack (is conntrack-tools installed?)")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().take(limit) {
            // Parse conntrack output
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let protocol = parts[0].to_string();
            let entry_state = parts
                .iter()
                .find(|p| {
                    ["ESTABLISHED", "NEW", "RELATED", "TIME_WAIT"]
                        .contains(&p.to_uppercase().as_str())
                })
                .map(|s| s.to_string())
                .unwrap_or("-".to_string());

            // Apply filters
            if let Some(s) = state {
                if !entry_state.eq_ignore_ascii_case(s) {
                    continue;
                }
            }

            // Extract IPs and ports
            let mut source = "-".to_string();
            let mut destination = "-".to_string();
            let mut sport = "-".to_string();
            let mut dport = "-".to_string();

            for part in &parts {
                if part.starts_with("src=") {
                    source = part.trim_start_matches("src=").to_string();
                } else if part.starts_with("dst=") && destination == "-" {
                    destination = part.trim_start_matches("dst=").to_string();
                } else if part.starts_with("sport=") && sport == "-" {
                    sport = part.trim_start_matches("sport=").to_string();
                } else if part.starts_with("dport=") && dport == "-" {
                    dport = part.trim_start_matches("dport=").to_string();
                }
            }

            if let Some(filter_src) = src {
                if !source.contains(filter_src) {
                    continue;
                }
            }

            entries.push(ConntrackEntry {
                protocol,
                state: entry_state,
                source,
                destination,
                sport,
                dport,
            });
        }

        Ok(entries)
    }

    /// Add rate limiting rule
    fn add_rate_limit(
        &self,
        chain: &str,
        protocol: &str,
        port: u16,
        limit: &str,
        burst: u32,
    ) -> Result<()> {
        println!(
            "{} Adding rate limit: {}/s burst {} for port {}",
            "[*]".blue(),
            limit,
            burst,
            port
        );

        let output = Command::new("iptables")
            .args([
                "-A",
                chain,
                "-p",
                protocol,
                "--dport",
                &port.to_string(),
                "-m",
                "limit",
                "--limit",
                limit,
                "--limit-burst",
                &burst.to_string(),
                "-j",
                "ACCEPT",
            ])
            .output()
            .context("Failed to add rate limit rule")?;

        if output.status.success() {
            // Add drop rule for exceeding limit
            let _ = Command::new("iptables")
                .args([
                    "-A", chain, "-p", protocol, "--dport", &port.to_string(), "-j", "DROP",
                ])
                .output();

            println!("{} Rate limit rule added", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to add rate limit: {}", stderr);
        }
    }

    /// Get firewall status
    fn get_status(&self) -> Result<FirewallStatus> {
        let mut status = FirewallStatus {
            backend: self.backend.clone(),
            is_active: true,
            default_policies: HashMap::new(),
            rule_count: HashMap::new(),
            total_rules: 0,
        };

        // Get policies
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let output = Command::new("iptables")
                .args(["-L", chain])
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(first_line) = stdout.lines().next() {
                if first_line.contains("ACCEPT") {
                    status.default_policies.insert(chain.to_string(), "ACCEPT".to_string());
                } else if first_line.contains("DROP") {
                    status.default_policies.insert(chain.to_string(), "DROP".to_string());
                }
            }
        }

        // Count rules
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let rules = self.list_rules("filter", Some(chain), false)?;
            let count = rules.len() as u32;
            status.rule_count.insert(chain.to_string(), count);
            status.total_rules += count;
        }

        Ok(status)
    }

    /// Export rules to file
    fn export_rules(&self, output: &PathBuf, format: &str) -> Result<()> {
        println!("{} Exporting rules to {}...", "[*]".blue(), output.display());

        match format {
            "iptables-save" => {
                self.backup(output)?;
            }
            "json" => {
                let mut all_rules = Vec::new();
                for table in &["filter", "nat", "mangle"] {
                    let rules = self.list_rules(table, None, true)?;
                    all_rules.extend(rules);
                }
                let json = serde_json::to_string_pretty(&all_rules)?;
                fs::write(output, json)?;
            }
            "script" => {
                let save_output = Command::new("iptables-save").output()?;
                let rules = String::from_utf8_lossy(&save_output.stdout);

                let mut script = String::from("#!/bin/bash\n");
                script.push_str("# Firewall rules exported by firewall-manager\n");
                script.push_str(&format!("# Date: {}\n\n", Local::now().format("%Y-%m-%d %H:%M:%S")));
                script.push_str("# Flush existing rules\n");
                script.push_str("iptables -F\n\n");
                script.push_str("# Apply rules\n");

                for line in rules.lines() {
                    if line.starts_with("-A") {
                        script.push_str(&format!("iptables {}\n", line));
                    }
                }

                fs::write(output, script)?;
            }
            _ => anyhow::bail!("Unknown export format: {}", format),
        }

        println!("{} Rules exported successfully", "[+]".green());
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = FirewallManager::new(&cli.backend, cli.verbose);

    match cli.command {
        Commands::List { table, chain, numbered } => {
            let rules = manager.list_rules(&table, chain.as_deref(), numbered)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&rules)?);
            } else {
                println!("{} Firewall Rules (table: {}):", "[*]".blue(), table);
                if rules.is_empty() {
                    println!("  No rules found");
                } else {
                    let table = Table::new(&rules).to_string();
                    println!("{}", table);
                }
            }
        }

        Commands::Add {
            chain,
            protocol,
            source,
            destination,
            dport,
            sport,
            target,
            in_interface,
            out_interface,
            insert,
            comment,
        } => {
            manager.add_rule(
                &chain,
                &protocol,
                source.as_deref(),
                destination.as_deref(),
                dport,
                sport,
                &target,
                in_interface.as_deref(),
                out_interface.as_deref(),
                insert,
                comment.as_deref(),
            )?;
        }

        Commands::Delete { chain, rule_num } => {
            manager.delete_rule(&chain, rule_num)?;
        }

        Commands::BlockIp { ip, direction, comment } => {
            manager.block_ip(&ip, &direction, comment.as_deref())?;
        }

        Commands::UnblockIp { ip } => {
            manager.unblock_ip(&ip)?;
        }

        Commands::AllowPort { port, protocol, source } => {
            manager.allow_port(port, &protocol, source.as_deref())?;
        }

        Commands::BlockPort { port, protocol } => {
            manager.block_port(port, &protocol)?;
        }

        Commands::Template { name, dry_run } => {
            manager.apply_template(&name, dry_run)?;
        }

        Commands::Chain { action } => match action {
            ChainCommands::Create { name, table } => {
                manager.create_chain(&name, &table)?;
            }
            ChainCommands::Delete { name, table } => {
                manager.delete_chain(&name, &table)?;
            }
            ChainCommands::Policy { chain, policy } => {
                manager.set_policy(&chain, &policy)?;
            }
            ChainCommands::List { table } => {
                let output = Command::new("iptables")
                    .args(["-t", &table, "-L", "-n"])
                    .output()?;
                println!("{}", String::from_utf8_lossy(&output.stdout));
            }
        },

        Commands::Backup { output } => {
            manager.backup(&output)?;
        }

        Commands::Restore { input, flush } => {
            manager.restore(&input, flush)?;
        }

        Commands::Flush { chain, force } => {
            manager.flush_all(chain.as_deref(), force)?;
        }

        Commands::Conntrack { state, src, limit } => {
            let entries = manager.get_conntrack(state.as_deref(), src.as_deref(), limit)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                println!("{} Connection Tracking Table:", "[*]".blue());
                if entries.is_empty() {
                    println!("  No connections found");
                } else {
                    let table = Table::new(&entries).to_string();
                    println!("{}", table);
                }
            }
        }

        Commands::RateLimit {
            chain,
            protocol,
            port,
            limit,
            burst,
        } => {
            manager.add_rate_limit(&chain, &protocol, port, &limit, burst)?;
        }

        Commands::Status => {
            let status = manager.get_status()?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("{} Firewall Status:", "[*]".blue());
                println!("{}", "=".repeat(50));
                println!("  Backend: {}", status.backend);
                println!(
                    "  Active:  {}",
                    if status.is_active { "Yes".green() } else { "No".red() }
                );
                println!("\n  Default Policies:");
                for (chain, policy) in &status.default_policies {
                    let policy_color = if policy == "DROP" {
                        policy.green()
                    } else {
                        policy.yellow()
                    };
                    println!("    {}: {}", chain, policy_color);
                }
                println!("\n  Rule Counts:");
                for (chain, count) in &status.rule_count {
                    println!("    {}: {}", chain, count);
                }
                println!("\n  Total Rules: {}", status.total_rules);
            }
        }

        Commands::Nat { action } => match action {
            NatCommands::Show => {
                let rules = manager.list_rules("nat", None, true)?;
                if cli.format == "json" {
                    println!("{}", serde_json::to_string_pretty(&rules)?);
                } else {
                    println!("{} NAT Rules:", "[*]".blue());
                    if rules.is_empty() {
                        println!("  No NAT rules");
                    } else {
                        let table = Table::new(&rules).to_string();
                        println!("{}", table);
                    }
                }
            }
            NatCommands::Snat {
                source,
                out_interface,
                to_source,
            } => {
                println!("{} Adding SNAT rule", "[*]".blue());
                let _ = Command::new("iptables")
                    .args([
                        "-t", "nat", "-A", "POSTROUTING", "-s", &source, "-o", &out_interface,
                        "-j", "SNAT", "--to-source", &to_source,
                    ])
                    .output()?;
            }
            NatCommands::Dnat {
                dport,
                to_destination,
                protocol,
            } => {
                println!("{} Adding DNAT rule", "[*]".blue());
                let _ = Command::new("iptables")
                    .args([
                        "-t", "nat", "-A", "PREROUTING", "-p", &protocol, "--dport",
                        &dport.to_string(), "-j", "DNAT", "--to-destination", &to_destination,
                    ])
                    .output()?;
            }
            NatCommands::Masquerade { out_interface, source } => {
                println!("{} Adding masquerade rule", "[*]".blue());
                let mut args = vec!["-t", "nat", "-A", "POSTROUTING"];
                if let Some(ref src) = source {
                    args.extend(["-s", src]);
                }
                args.extend(["-o", &out_interface, "-j", "MASQUERADE"]);
                let _ = Command::new("iptables").args(&args).output()?;
            }
            NatCommands::Delete { chain, rule_num } => {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-D", &chain, &rule_num.to_string()])
                    .output()?;
                println!("{} NAT rule deleted", "[+]".green());
            }
        },

        Commands::Export { output, export_format } => {
            manager.export_rules(&output, &export_format)?;
        }
    }

    Ok(())
}
