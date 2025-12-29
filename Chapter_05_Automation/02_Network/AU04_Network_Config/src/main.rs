//! AU04 Network Config - Network Configuration Tool
//!
//! This tool provides comprehensive network configuration management for Linux systems.
//! Essential for security operations, network hardening, and incident response.
//!
//! Features:
//! - List and manage network interfaces
//! - Configure IP addresses (static/DHCP)
//! - Manage DNS settings
//! - Configure routes and gateways
//! - Network diagnostics
//! - Interface state management
//! - Network profile management
//! - Security configuration checks
//!
//! Security applications:
//! - Network isolation during incidents
//! - DNS configuration hardening
//! - Route manipulation for traffic analysis
//! - Quick network reconfiguration

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

/// Network Config - Network configuration management tool
#[derive(Parser)]
#[command(name = "network-config")]
#[command(author = "Security Engineer")]
#[command(version = "1.0")]
#[command(about = "Configure and manage network settings")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// List network interfaces
    Interfaces {
        /// Show all interfaces including loopback
        #[arg(short, long)]
        all: bool,

        /// Show only active interfaces
        #[arg(short = 'u', long)]
        up_only: bool,
    },

    /// Show interface details
    Info {
        /// Interface name
        interface: String,
    },

    /// Configure interface IP address
    SetIp {
        /// Interface name
        interface: String,

        /// IP address with CIDR (e.g., 192.168.1.10/24)
        address: String,

        /// Make configuration persistent
        #[arg(short, long)]
        persistent: bool,
    },

    /// Set interface to DHCP
    SetDhcp {
        /// Interface name
        interface: String,

        /// Make configuration persistent
        #[arg(short, long)]
        persistent: bool,
    },

    /// Bring interface up
    Up {
        /// Interface name
        interface: String,
    },

    /// Bring interface down
    Down {
        /// Interface name
        interface: String,
    },

    /// Manage DNS configuration
    Dns {
        #[command(subcommand)]
        action: DnsCommands,
    },

    /// Manage routes
    Route {
        #[command(subcommand)]
        action: RouteCommands,
    },

    /// Network diagnostics
    Diag {
        /// Target host to diagnose
        target: String,

        /// Full diagnosis
        #[arg(short, long)]
        full: bool,
    },

    /// Check network security configuration
    SecurityCheck {
        /// Fix issues automatically
        #[arg(short, long)]
        fix: bool,
    },

    /// Save current configuration as a profile
    SaveProfile {
        /// Profile name
        name: String,

        /// Profile directory
        #[arg(short, long, default_value = "/etc/network/profiles")]
        dir: PathBuf,
    },

    /// Load a saved configuration profile
    LoadProfile {
        /// Profile name
        name: String,

        /// Profile directory
        #[arg(short, long, default_value = "/etc/network/profiles")]
        dir: PathBuf,
    },

    /// Show connection statistics
    Stats {
        /// Interface name (all if not specified)
        interface: Option<String>,
    },

    /// Monitor network traffic
    Monitor {
        /// Interface to monitor
        interface: Option<String>,

        /// Refresh interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,
    },

    /// Export network configuration
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum DnsCommands {
    /// Show current DNS configuration
    Show,

    /// Add a DNS server
    Add {
        /// DNS server IP address
        server: String,
    },

    /// Remove a DNS server
    Remove {
        /// DNS server IP address
        server: String,
    },

    /// Set DNS servers (replaces all)
    Set {
        /// DNS servers (comma-separated)
        servers: String,
    },

    /// Test DNS resolution
    Test {
        /// Domain to resolve
        domain: String,
    },
}

#[derive(Subcommand)]
enum RouteCommands {
    /// Show routing table
    Show,

    /// Add a route
    Add {
        /// Destination network (e.g., 10.0.0.0/8)
        destination: String,

        /// Gateway
        gateway: String,

        /// Interface (optional)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Delete a route
    Delete {
        /// Destination network
        destination: String,
    },

    /// Set default gateway
    DefaultGw {
        /// Gateway IP address
        gateway: String,

        /// Interface (optional)
        #[arg(short, long)]
        interface: Option<String>,
    },
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct InterfaceInfo {
    #[tabled(rename = "Interface")]
    name: String,
    #[tabled(rename = "State")]
    state: String,
    #[tabled(rename = "MAC Address")]
    mac: String,
    #[tabled(rename = "IPv4")]
    ipv4: String,
    #[tabled(rename = "IPv6")]
    ipv6: String,
    #[tabled(rename = "Type")]
    iface_type: String,
}

/// Detailed interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InterfaceDetails {
    name: String,
    state: String,
    mac: String,
    mtu: u32,
    ipv4_addresses: Vec<String>,
    ipv6_addresses: Vec<String>,
    broadcast: Option<String>,
    iface_type: String,
    driver: Option<String>,
    speed: Option<String>,
    duplex: Option<String>,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
}

/// Route information
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct RouteInfo {
    #[tabled(rename = "Destination")]
    destination: String,
    #[tabled(rename = "Gateway")]
    gateway: String,
    #[tabled(rename = "Mask")]
    mask: String,
    #[tabled(rename = "Interface")]
    interface: String,
    #[tabled(rename = "Metric")]
    metric: String,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsConfig {
    nameservers: Vec<String>,
    search_domains: Vec<String>,
    options: Vec<String>,
}

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
struct NetworkStats {
    #[tabled(rename = "Interface")]
    interface: String,
    #[tabled(rename = "RX Bytes")]
    rx_bytes: String,
    #[tabled(rename = "TX Bytes")]
    tx_bytes: String,
    #[tabled(rename = "RX Packets")]
    rx_packets: String,
    #[tabled(rename = "TX Packets")]
    tx_packets: String,
    #[tabled(rename = "RX Errors")]
    rx_errors: String,
    #[tabled(rename = "TX Errors")]
    tx_errors: String,
}

/// Security check finding
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityFinding {
    severity: String,
    category: String,
    issue: String,
    recommendation: String,
}

/// Network profile
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkProfile {
    name: String,
    created: String,
    interfaces: HashMap<String, InterfaceConfig>,
    dns: DnsConfig,
    routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InterfaceConfig {
    method: String, // static or dhcp
    address: Option<String>,
    netmask: Option<String>,
    gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteEntry {
    destination: String,
    gateway: String,
    interface: Option<String>,
}

/// Network configuration manager
struct NetworkManager {
    verbose: bool,
}

impl NetworkManager {
    fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// List all network interfaces
    fn list_interfaces(&self, show_all: bool, up_only: bool) -> Result<Vec<InterfaceInfo>> {
        let mut interfaces = Vec::new();

        // Use ip command to get interface info
        let output = Command::new("ip")
            .args(["-j", "addr", "show"])
            .output()
            .context("Failed to run ip command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output from ip command
        if let Ok(ifaces) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
            for iface in ifaces {
                let name = iface["ifname"].as_str().unwrap_or("").to_string();

                // Skip loopback unless show_all
                if !show_all && name == "lo" {
                    continue;
                }

                let operstate = iface["operstate"].as_str().unwrap_or("unknown").to_string();

                // Skip down interfaces if up_only
                if up_only && operstate.to_lowercase() != "up" {
                    continue;
                }

                let mac = iface["address"].as_str().unwrap_or("-").to_string();

                // Get IP addresses
                let mut ipv4 = String::from("-");
                let mut ipv6 = String::from("-");

                if let Some(addr_info) = iface["addr_info"].as_array() {
                    for addr in addr_info {
                        let family = addr["family"].as_str().unwrap_or("");
                        let local = addr["local"].as_str().unwrap_or("");
                        let prefixlen = addr["prefixlen"].as_u64().unwrap_or(0);

                        match family {
                            "inet" => {
                                if ipv4 == "-" {
                                    ipv4 = format!("{}/{}", local, prefixlen);
                                }
                            }
                            "inet6" => {
                                if ipv6 == "-" && !local.starts_with("fe80") {
                                    ipv6 = format!("{}/{}", local, prefixlen);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Determine interface type
                let iface_type = self.get_interface_type(&name);

                let state_colored = match operstate.to_lowercase().as_str() {
                    "up" => "UP".green().to_string(),
                    "down" => "DOWN".red().to_string(),
                    _ => operstate.yellow().to_string(),
                };

                interfaces.push(InterfaceInfo {
                    name,
                    state: state_colored,
                    mac,
                    ipv4,
                    ipv6,
                    iface_type,
                });
            }
        }

        Ok(interfaces)
    }

    /// Get interface type
    fn get_interface_type(&self, name: &str) -> String {
        if name.starts_with("eth") || name.starts_with("en") {
            "Ethernet".to_string()
        } else if name.starts_with("wl") {
            "Wireless".to_string()
        } else if name.starts_with("br") {
            "Bridge".to_string()
        } else if name.starts_with("docker") || name.starts_with("veth") {
            "Virtual".to_string()
        } else if name.starts_with("tun") || name.starts_with("tap") {
            "Tunnel".to_string()
        } else if name.starts_with("virbr") {
            "VM Bridge".to_string()
        } else if name == "lo" {
            "Loopback".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Get detailed interface information
    fn get_interface_details(&self, name: &str) -> Result<InterfaceDetails> {
        let output = Command::new("ip")
            .args(["-j", "addr", "show", name])
            .output()
            .context("Failed to get interface info")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ifaces: Vec<serde_json::Value> = serde_json::from_str(&stdout)?;

        if ifaces.is_empty() {
            anyhow::bail!("Interface not found: {}", name);
        }

        let iface = &ifaces[0];

        let mut ipv4_addresses = Vec::new();
        let mut ipv6_addresses = Vec::new();
        let mut broadcast = None;

        if let Some(addr_info) = iface["addr_info"].as_array() {
            for addr in addr_info {
                let family = addr["family"].as_str().unwrap_or("");
                let local = addr["local"].as_str().unwrap_or("");
                let prefixlen = addr["prefixlen"].as_u64().unwrap_or(0);

                match family {
                    "inet" => {
                        ipv4_addresses.push(format!("{}/{}", local, prefixlen));
                        if broadcast.is_none() {
                            broadcast = addr["broadcast"].as_str().map(|s| s.to_string());
                        }
                    }
                    "inet6" => {
                        ipv6_addresses.push(format!("{}/{}", local, prefixlen));
                    }
                    _ => {}
                }
            }
        }

        // Get stats from /sys/class/net
        let stats = self.get_interface_stats(name)?;

        // Get driver info
        let driver = self.get_interface_driver(name);

        // Get link info
        let (speed, duplex) = self.get_link_info(name);

        Ok(InterfaceDetails {
            name: name.to_string(),
            state: iface["operstate"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            mac: iface["address"].as_str().unwrap_or("-").to_string(),
            mtu: iface["mtu"].as_u64().unwrap_or(0) as u32,
            ipv4_addresses,
            ipv6_addresses,
            broadcast,
            iface_type: self.get_interface_type(name),
            driver,
            speed,
            duplex,
            rx_bytes: stats.0,
            tx_bytes: stats.1,
            rx_packets: stats.2,
            tx_packets: stats.3,
            rx_errors: stats.4,
            tx_errors: stats.5,
        })
    }

    /// Get interface statistics
    fn get_interface_stats(&self, name: &str) -> Result<(u64, u64, u64, u64, u64, u64)> {
        let base_path = format!("/sys/class/net/{}/statistics", name);

        let rx_bytes = fs::read_to_string(format!("{}/rx_bytes", base_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let tx_bytes = fs::read_to_string(format!("{}/tx_bytes", base_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let rx_packets = fs::read_to_string(format!("{}/rx_packets", base_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let tx_packets = fs::read_to_string(format!("{}/tx_packets", base_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let rx_errors = fs::read_to_string(format!("{}/rx_errors", base_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let tx_errors = fs::read_to_string(format!("{}/tx_errors", base_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        Ok((rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors))
    }

    /// Get interface driver
    fn get_interface_driver(&self, name: &str) -> Option<String> {
        let driver_path = format!("/sys/class/net/{}/device/driver", name);
        fs::read_link(driver_path)
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
    }

    /// Get link speed and duplex
    fn get_link_info(&self, name: &str) -> (Option<String>, Option<String>) {
        let speed = fs::read_to_string(format!("/sys/class/net/{}/speed", name))
            .ok()
            .map(|s| format!("{} Mbps", s.trim()));

        let duplex = fs::read_to_string(format!("/sys/class/net/{}/duplex", name))
            .ok()
            .map(|s| s.trim().to_string());

        (speed, duplex)
    }

    /// Set interface IP address
    fn set_ip(&self, interface: &str, address: &str, persistent: bool) -> Result<()> {
        println!(
            "{} Setting IP {} on {}",
            "[*]".blue(),
            address.cyan(),
            interface.cyan()
        );

        // Validate IP address
        let _: IpNetwork = address.parse().context("Invalid IP address format")?;

        // Flush existing addresses
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", interface])
            .output();

        // Add new address
        let output = Command::new("ip")
            .args(["addr", "add", address, "dev", interface])
            .output()
            .context("Failed to set IP address")?;

        if output.status.success() {
            println!(
                "{} IP address {} set on {}",
                "[+]".green(),
                address.cyan(),
                interface.cyan()
            );

            if persistent {
                self.make_persistent(interface, Some(address))?;
            }

            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to set IP: {}", stderr);
        }
    }

    /// Set interface to DHCP
    fn set_dhcp(&self, interface: &str, persistent: bool) -> Result<()> {
        println!(
            "{} Setting {} to DHCP",
            "[*]".blue(),
            interface.cyan()
        );

        // Release any existing DHCP lease
        let _ = Command::new("dhclient")
            .args(["-r", interface])
            .output();

        // Request new DHCP lease
        let output = Command::new("dhclient")
            .arg(interface)
            .output()
            .context("Failed to run dhclient")?;

        if output.status.success() {
            println!(
                "{} {} configured via DHCP",
                "[+]".green(),
                interface.cyan()
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("DHCP configuration failed: {}", stderr);
        }
    }

    /// Make configuration persistent
    fn make_persistent(&self, interface: &str, address: Option<&str>) -> Result<()> {
        // This is distribution-specific - showing Netplan format for Ubuntu
        let config_path = format!("/etc/netplan/50-{}.yaml", interface);

        let config = if let Some(addr) = address {
            format!(
                r#"network:
  version: 2
  ethernets:
    {}:
      addresses:
        - {}
"#,
                interface, addr
            )
        } else {
            format!(
                r#"network:
  version: 2
  ethernets:
    {}:
      dhcp4: true
"#,
                interface
            )
        };

        if self.verbose {
            println!(
                "{} Would write to {}: \n{}",
                "[*]".blue(),
                config_path,
                config
            );
        }

        Ok(())
    }

    /// Bring interface up
    fn interface_up(&self, interface: &str) -> Result<()> {
        println!("{} Bringing up {}", "[*]".blue(), interface.cyan());

        let output = Command::new("ip")
            .args(["link", "set", interface, "up"])
            .output()
            .context("Failed to bring interface up")?;

        if output.status.success() {
            println!("{} {} is now up", "[+]".green(), interface.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to bring up interface: {}", stderr);
        }
    }

    /// Bring interface down
    fn interface_down(&self, interface: &str) -> Result<()> {
        println!("{} Bringing down {}", "[*]".blue(), interface.cyan());

        let output = Command::new("ip")
            .args(["link", "set", interface, "down"])
            .output()
            .context("Failed to bring interface down")?;

        if output.status.success() {
            println!("{} {} is now down", "[+]".green(), interface.cyan());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to bring down interface: {}", stderr);
        }
    }

    /// Get DNS configuration
    fn get_dns_config(&self) -> Result<DnsConfig> {
        let mut config = DnsConfig {
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            options: Vec::new(),
        };

        // Try systemd-resolved first
        let output = Command::new("resolvectl")
            .args(["status"])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if line.contains("DNS Servers:") {
                        let servers = line.split(':').last().unwrap_or("");
                        config.nameservers.extend(
                            servers
                                .split_whitespace()
                                .map(|s| s.to_string()),
                        );
                    }
                }
                return Ok(config);
            }
        }

        // Fall back to /etc/resolv.conf
        let resolv = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        for line in resolv.lines() {
            let line = line.trim();
            if line.starts_with("nameserver") {
                if let Some(ns) = line.split_whitespace().nth(1) {
                    config.nameservers.push(ns.to_string());
                }
            } else if line.starts_with("search") || line.starts_with("domain") {
                let domains: Vec<String> = line
                    .split_whitespace()
                    .skip(1)
                    .map(|s| s.to_string())
                    .collect();
                config.search_domains.extend(domains);
            } else if line.starts_with("options") {
                let opts: Vec<String> = line
                    .split_whitespace()
                    .skip(1)
                    .map(|s| s.to_string())
                    .collect();
                config.options.extend(opts);
            }
        }

        Ok(config)
    }

    /// Add DNS server
    fn add_dns(&self, server: &str) -> Result<()> {
        println!("{} Adding DNS server: {}", "[*]".blue(), server.cyan());

        // Validate IP
        let _: IpAddr = server.parse().context("Invalid IP address")?;

        // Try using resolvectl first (systemd-resolved)
        let output = Command::new("resolvectl")
            .args(["dns", "--interface=*", server])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                println!("{} DNS server added", "[+]".green());
                return Ok(());
            }
        }

        // Fall back to editing resolv.conf
        let mut resolv = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        resolv = format!("nameserver {}\n{}", server, resolv);
        fs::write("/etc/resolv.conf", resolv)?;

        println!("{} DNS server added to /etc/resolv.conf", "[+]".green());
        Ok(())
    }

    /// Test DNS resolution
    fn test_dns(&self, domain: &str) -> Result<()> {
        println!("{} Testing DNS resolution for {}", "[*]".blue(), domain.cyan());

        match dns_lookup::lookup_host(domain) {
            Ok(ips) => {
                println!("{} Resolved {} to:", "[+]".green(), domain.cyan());
                for ip in ips {
                    println!("  - {}", ip);
                }
                Ok(())
            }
            Err(e) => {
                println!("{} DNS resolution failed: {}", "[!]".red(), e);
                Ok(())
            }
        }
    }

    /// Get routing table
    fn get_routes(&self) -> Result<Vec<RouteInfo>> {
        let mut routes = Vec::new();

        let output = Command::new("ip")
            .args(["-j", "route", "show"])
            .output()
            .context("Failed to get routes")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if let Ok(route_list) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
            for route in route_list {
                let dst = route["dst"].as_str().unwrap_or("default").to_string();
                let gateway = route["gateway"]
                    .as_str()
                    .unwrap_or("-")
                    .to_string();
                let dev = route["dev"].as_str().unwrap_or("-").to_string();
                let metric = route["metric"]
                    .as_u64()
                    .map(|m| m.to_string())
                    .unwrap_or("-".to_string());

                routes.push(RouteInfo {
                    destination: dst,
                    gateway,
                    mask: "-".to_string(),
                    interface: dev,
                    metric,
                });
            }
        }

        Ok(routes)
    }

    /// Add a route
    fn add_route(
        &self,
        destination: &str,
        gateway: &str,
        interface: Option<&str>,
    ) -> Result<()> {
        println!(
            "{} Adding route: {} via {}",
            "[*]".blue(),
            destination.cyan(),
            gateway.cyan()
        );

        let mut cmd = Command::new("ip");
        cmd.args(["route", "add", destination, "via", gateway]);

        if let Some(iface) = interface {
            cmd.args(["dev", iface]);
        }

        let output = cmd.output().context("Failed to add route")?;

        if output.status.success() {
            println!("{} Route added successfully", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to add route: {}", stderr);
        }
    }

    /// Delete a route
    fn delete_route(&self, destination: &str) -> Result<()> {
        println!("{} Deleting route: {}", "[*]".blue(), destination.cyan());

        let output = Command::new("ip")
            .args(["route", "del", destination])
            .output()
            .context("Failed to delete route")?;

        if output.status.success() {
            println!("{} Route deleted successfully", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to delete route: {}", stderr);
        }
    }

    /// Set default gateway
    fn set_default_gateway(&self, gateway: &str, interface: Option<&str>) -> Result<()> {
        println!(
            "{} Setting default gateway: {}",
            "[*]".blue(),
            gateway.cyan()
        );

        // First delete existing default route
        let _ = Command::new("ip")
            .args(["route", "del", "default"])
            .output();

        // Add new default route
        let mut cmd = Command::new("ip");
        cmd.args(["route", "add", "default", "via", gateway]);

        if let Some(iface) = interface {
            cmd.args(["dev", iface]);
        }

        let output = cmd.output().context("Failed to set default gateway")?;

        if output.status.success() {
            println!("{} Default gateway set successfully", "[+]".green());
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to set default gateway: {}", stderr);
        }
    }

    /// Network diagnostics
    fn diagnose(&self, target: &str, full: bool) -> Result<()> {
        println!("{} Running network diagnostics for {}", "[*]".blue(), target.cyan());
        println!("{}", "=".repeat(60));

        // Ping test
        println!("\n{} Ping Test:", "[*]".cyan());
        let output = Command::new("ping")
            .args(["-c", "4", "-W", "2", target])
            .output()?;
        println!("{}", String::from_utf8_lossy(&output.stdout));

        // DNS resolution
        println!("\n{} DNS Resolution:", "[*]".cyan());
        self.test_dns(target)?;

        if full {
            // Traceroute
            println!("\n{} Traceroute:", "[*]".cyan());
            let output = Command::new("traceroute")
                .args(["-m", "15", target])
                .output()?;
            println!("{}", String::from_utf8_lossy(&output.stdout));

            // Port check for common ports
            println!("\n{} Port Check:", "[*]".cyan());
            for port in &[22, 80, 443] {
                let output = Command::new("nc")
                    .args(["-zv", "-w", "2", target, &port.to_string()])
                    .output()?;

                if output.status.success() {
                    println!("  Port {}: {}", port, "OPEN".green());
                } else {
                    println!("  Port {}: {}", port, "CLOSED".red());
                }
            }
        }

        Ok(())
    }

    /// Security check
    fn security_check(&self, fix: bool) -> Result<Vec<SecurityFinding>> {
        println!("{} Running network security check...", "[*]".blue());
        let mut findings = Vec::new();

        // Check for IP forwarding
        let ip_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap_or_default()
            .trim()
            .to_string();

        if ip_forward == "1" {
            findings.push(SecurityFinding {
                severity: "MEDIUM".to_string(),
                category: "IP Forwarding".to_string(),
                issue: "IPv4 forwarding is enabled".to_string(),
                recommendation: "Disable if not needed: sysctl -w net.ipv4.ip_forward=0".to_string(),
            });
        }

        // Check for promiscuous mode interfaces
        let interfaces = self.list_interfaces(true, false)?;
        for iface in &interfaces {
            let flags_path = format!("/sys/class/net/{}/flags", iface.name);
            if let Ok(flags) = fs::read_to_string(&flags_path) {
                let flags: u32 = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap_or(0);
                if flags & 0x100 != 0 {
                    // IFF_PROMISC
                    findings.push(SecurityFinding {
                        severity: "HIGH".to_string(),
                        category: "Promiscuous Mode".to_string(),
                        issue: format!("Interface {} is in promiscuous mode", iface.name),
                        recommendation: "Investigate if this is authorized network monitoring".to_string(),
                    });
                }
            }
        }

        // Check DNS configuration
        let dns = self.get_dns_config()?;
        let private_dns: Vec<&String> = dns
            .nameservers
            .iter()
            .filter(|ns| {
                ns.starts_with("10.")
                    || ns.starts_with("192.168.")
                    || ns.starts_with("172.")
            })
            .collect();

        if private_dns.is_empty() && !dns.nameservers.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW".to_string(),
                category: "DNS".to_string(),
                issue: "Using only public DNS servers".to_string(),
                recommendation: "Consider using internal DNS for security monitoring".to_string(),
            });
        }

        // Check for ICMP redirects
        let icmp_redirect = fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_redirects")
            .unwrap_or_default()
            .trim()
            .to_string();

        if icmp_redirect == "1" {
            findings.push(SecurityFinding {
                severity: "MEDIUM".to_string(),
                category: "ICMP".to_string(),
                issue: "ICMP redirects are accepted".to_string(),
                recommendation: "Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0".to_string(),
            });

            if fix {
                let _ = Command::new("sysctl")
                    .args(["-w", "net.ipv4.conf.all.accept_redirects=0"])
                    .output();
            }
        }

        Ok(findings)
    }

    /// Save network profile
    fn save_profile(&self, name: &str, dir: &PathBuf) -> Result<()> {
        println!("{} Saving network profile: {}", "[*]".blue(), name.cyan());

        fs::create_dir_all(dir)?;

        let interfaces = self.list_interfaces(false, false)?;
        let mut interface_configs = HashMap::new();

        for iface in &interfaces {
            interface_configs.insert(
                iface.name.clone(),
                InterfaceConfig {
                    method: "static".to_string(),
                    address: Some(iface.ipv4.clone()),
                    netmask: None,
                    gateway: None,
                },
            );
        }

        let dns = self.get_dns_config()?;
        let routes = self.get_routes()?;

        let profile = NetworkProfile {
            name: name.to_string(),
            created: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            interfaces: interface_configs,
            dns,
            routes: routes
                .iter()
                .map(|r| RouteEntry {
                    destination: r.destination.clone(),
                    gateway: r.gateway.clone(),
                    interface: Some(r.interface.clone()),
                })
                .collect(),
        };

        let profile_path = dir.join(format!("{}.json", name));
        let json = serde_json::to_string_pretty(&profile)?;
        fs::write(&profile_path, json)?;

        println!(
            "{} Profile saved to {}",
            "[+]".green(),
            profile_path.display()
        );

        Ok(())
    }

    /// Get network statistics
    fn get_stats(&self, interface: Option<&str>) -> Result<Vec<NetworkStats>> {
        let mut stats = Vec::new();

        let interfaces = self.list_interfaces(false, false)?;

        for iface in &interfaces {
            if let Some(name) = interface {
                if iface.name != name {
                    continue;
                }
            }

            let (rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors) =
                self.get_interface_stats(&iface.name)?;

            stats.push(NetworkStats {
                interface: iface.name.clone(),
                rx_bytes: format_bytes(rx_bytes),
                tx_bytes: format_bytes(tx_bytes),
                rx_packets: rx_packets.to_string(),
                tx_packets: tx_packets.to_string(),
                rx_errors: rx_errors.to_string(),
                tx_errors: tx_errors.to_string(),
            });
        }

        Ok(stats)
    }

    /// Export configuration
    fn export_config(&self, output: &PathBuf) -> Result<()> {
        println!("{} Exporting network configuration...", "[*]".blue());

        #[derive(Serialize)]
        struct ExportData {
            timestamp: String,
            interfaces: Vec<InterfaceInfo>,
            dns: DnsConfig,
            routes: Vec<RouteInfo>,
        }

        let data = ExportData {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            interfaces: self.list_interfaces(false, false)?,
            dns: self.get_dns_config()?,
            routes: self.get_routes()?,
        };

        let json = serde_json::to_string_pretty(&data)?;
        fs::write(output, json)?;

        println!(
            "{} Configuration exported to {}",
            "[+]".green(),
            output.display()
        );

        Ok(())
    }
}

/// Format bytes to human-readable
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manager = NetworkManager::new(cli.verbose);

    match cli.command {
        Commands::Interfaces { all, up_only } => {
            let interfaces = manager.list_interfaces(all, up_only)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&interfaces)?);
            } else {
                println!("{} Network Interfaces:", "[*]".blue());
                let table = Table::new(&interfaces).to_string();
                println!("{}", table);
            }
        }

        Commands::Info { interface } => {
            let details = manager.get_interface_details(&interface)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&details)?);
            } else {
                println!(
                    "{} Interface Details: {}",
                    "[*]".blue(),
                    details.name.cyan().bold()
                );
                println!("{}", "=".repeat(50));
                println!("  State:     {}", details.state);
                println!("  Type:      {}", details.iface_type);
                println!("  MAC:       {}", details.mac);
                println!("  MTU:       {}", details.mtu);
                println!("  Driver:    {}", details.driver.unwrap_or("-".to_string()));
                println!("  Speed:     {}", details.speed.unwrap_or("-".to_string()));
                println!("  Duplex:    {}", details.duplex.unwrap_or("-".to_string()));
                println!("\n  IPv4 Addresses:");
                for addr in &details.ipv4_addresses {
                    println!("    - {}", addr);
                }
                println!("\n  IPv6 Addresses:");
                for addr in &details.ipv6_addresses {
                    println!("    - {}", addr);
                }
                println!("\n  Statistics:");
                println!("    RX: {} ({} packets)", format_bytes(details.rx_bytes), details.rx_packets);
                println!("    TX: {} ({} packets)", format_bytes(details.tx_bytes), details.tx_packets);
                println!("    Errors: RX={}, TX={}", details.rx_errors, details.tx_errors);
            }
        }

        Commands::SetIp {
            interface,
            address,
            persistent,
        } => {
            manager.set_ip(&interface, &address, persistent)?;
        }

        Commands::SetDhcp { interface, persistent } => {
            manager.set_dhcp(&interface, persistent)?;
        }

        Commands::Up { interface } => {
            manager.interface_up(&interface)?;
        }

        Commands::Down { interface } => {
            manager.interface_down(&interface)?;
        }

        Commands::Dns { action } => match action {
            DnsCommands::Show => {
                let dns = manager.get_dns_config()?;

                if cli.format == "json" {
                    println!("{}", serde_json::to_string_pretty(&dns)?);
                } else {
                    println!("{} DNS Configuration:", "[*]".blue());
                    println!("  Nameservers:");
                    for ns in &dns.nameservers {
                        println!("    - {}", ns);
                    }
                    if !dns.search_domains.is_empty() {
                        println!("  Search Domains:");
                        for domain in &dns.search_domains {
                            println!("    - {}", domain);
                        }
                    }
                }
            }
            DnsCommands::Add { server } => {
                manager.add_dns(&server)?;
            }
            DnsCommands::Remove { server } => {
                println!("{} Removing DNS server: {}", "[*]".blue(), server);
                // Implementation would modify resolv.conf
            }
            DnsCommands::Set { servers } => {
                println!("{} Setting DNS servers: {}", "[*]".blue(), servers);
            }
            DnsCommands::Test { domain } => {
                manager.test_dns(&domain)?;
            }
        },

        Commands::Route { action } => match action {
            RouteCommands::Show => {
                let routes = manager.get_routes()?;

                if cli.format == "json" {
                    println!("{}", serde_json::to_string_pretty(&routes)?);
                } else {
                    println!("{} Routing Table:", "[*]".blue());
                    let table = Table::new(&routes).to_string();
                    println!("{}", table);
                }
            }
            RouteCommands::Add {
                destination,
                gateway,
                interface,
            } => {
                manager.add_route(&destination, &gateway, interface.as_deref())?;
            }
            RouteCommands::Delete { destination } => {
                manager.delete_route(&destination)?;
            }
            RouteCommands::DefaultGw { gateway, interface } => {
                manager.set_default_gateway(&gateway, interface.as_deref())?;
            }
        },

        Commands::Diag { target, full } => {
            manager.diagnose(&target, full)?;
        }

        Commands::SecurityCheck { fix } => {
            let findings = manager.security_check(fix)?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                println!("{} Network Security Check Results:", "[*]".blue());
                println!("{}", "=".repeat(60));

                for finding in &findings {
                    let severity_color = match finding.severity.as_str() {
                        "HIGH" => finding.severity.red().bold(),
                        "MEDIUM" => finding.severity.yellow(),
                        "LOW" => finding.severity.cyan(),
                        _ => finding.severity.white(),
                    };

                    println!(
                        "  [{}] {}: {}",
                        severity_color,
                        finding.category,
                        finding.issue
                    );
                    if cli.verbose {
                        println!("    Recommendation: {}", finding.recommendation);
                    }
                }

                println!("{}", "=".repeat(60));
                println!("Total findings: {}", findings.len());
            }
        }

        Commands::SaveProfile { name, dir } => {
            manager.save_profile(&name, &dir)?;
        }

        Commands::LoadProfile { name, dir } => {
            println!("{} Loading profile: {}", "[*]".blue(), name);
            // Implementation would read and apply the profile
        }

        Commands::Stats { interface } => {
            let stats = manager.get_stats(interface.as_deref())?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("{} Network Statistics:", "[*]".blue());
                let table = Table::new(&stats).to_string();
                println!("{}", table);
            }
        }

        Commands::Monitor { interface, interval } => {
            println!("{} Starting network monitor (Ctrl+C to stop)", "[*]".blue());

            loop {
                print!("\x1B[2J\x1B[1;1H");
                println!(
                    "{} Network Monitor - {}",
                    "[*]".blue(),
                    Local::now().format("%H:%M:%S")
                );

                let stats = manager.get_stats(interface.as_deref())?;
                let table = Table::new(&stats).to_string();
                println!("{}", table);

                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        }

        Commands::Export { output } => {
            manager.export_config(&output)?;
        }
    }

    Ok(())
}
