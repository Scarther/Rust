//! # IP Validator - Network Security IP Address Tool
//!
//! Validates and analyzes IP addresses and CIDR notation for security applications.
//! Use cases include:
//! - Validating IP addresses from logs and configs
//! - CIDR range calculations for firewall rules
//! - Identifying private vs public IP addresses
//! - Checking if IPs belong to specific networks
//!
//! ## Rust Concepts Covered:
//! - Networking primitives (IpAddr, Ipv4Addr, Ipv6Addr)
//! - External crate usage (ipnetwork)
//! - Trait implementations
//! - Enum pattern matching
//! - Error handling with custom types
//! - Serialization with serde
//! - Iterator methods

use clap::{Parser, Subcommand};
use colored::*;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// IP Validator - Network security IP address analysis tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate and analyze an IP address
    Validate {
        /// IP address to validate
        ip: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Parse and analyze CIDR notation
    Cidr {
        /// CIDR notation (e.g., 192.168.1.0/24)
        cidr: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Check if an IP is in a CIDR range
    Contains {
        /// CIDR network
        cidr: String,

        /// IP address to check
        ip: String,
    },

    /// List all IPs in a CIDR range (limited to /24 or smaller for IPv4)
    List {
        /// CIDR notation
        cidr: String,

        /// Maximum number of IPs to list
        #[arg(short, long, default_value = "256")]
        limit: usize,
    },

    /// Get network information for multiple IPs
    Bulk {
        /// IP addresses (comma-separated or file path)
        input: String,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Compare two IP addresses
    Compare {
        /// First IP address
        ip1: String,

        /// Second IP address
        ip2: String,
    },

    /// Generate common private network ranges
    Private {
        /// Show IPv6 ranges too
        #[arg(short = '6', long)]
        ipv6: bool,
    },
}

/// Result of IP address validation
#[derive(Debug, Serialize, Deserialize)]
struct IpAnalysis {
    /// Original input
    input: String,
    /// Whether the IP is valid
    valid: bool,
    /// IP version (4 or 6)
    version: Option<u8>,
    /// Canonical form of the IP
    canonical: Option<String>,
    /// IP type classification
    ip_type: Option<String>,
    /// Whether it's a private address
    is_private: bool,
    /// Whether it's a loopback address
    is_loopback: bool,
    /// Whether it's a multicast address
    is_multicast: bool,
    /// Whether it's link-local
    is_link_local: bool,
    /// Whether it's a documentation address
    is_documentation: bool,
    /// Binary representation
    binary: Option<String>,
    /// Hexadecimal representation (for IPv4)
    hex: Option<String>,
    /// Reverse DNS format
    reverse_dns: Option<String>,
    /// Error message if invalid
    error: Option<String>,
}

/// Result of CIDR analysis
#[derive(Debug, Serialize, Deserialize)]
struct CidrAnalysis {
    /// Original input
    input: String,
    /// Whether the CIDR is valid
    valid: bool,
    /// Network address
    network: Option<String>,
    /// Broadcast address (IPv4 only)
    broadcast: Option<String>,
    /// First usable host
    first_host: Option<String>,
    /// Last usable host
    last_host: Option<String>,
    /// Subnet mask
    netmask: Option<String>,
    /// Wildcard mask (inverse)
    wildcard: Option<String>,
    /// CIDR prefix length
    prefix: Option<u8>,
    /// Total number of addresses
    total_addresses: Option<u128>,
    /// Number of usable hosts
    usable_hosts: Option<u128>,
    /// IP version
    version: Option<u8>,
    /// Error message if invalid
    error: Option<String>,
}

/// Custom error type for IP operations
#[derive(Debug)]
enum IpError {
    InvalidIp(String),
    InvalidCidr(String),
    ParseError(String),
}

impl std::fmt::Display for IpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpError::InvalidIp(msg) => write!(f, "Invalid IP: {}", msg),
            IpError::InvalidCidr(msg) => write!(f, "Invalid CIDR: {}", msg),
            IpError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for IpError {}

/// Classifies an IP address type
///
/// Demonstrates pattern matching with IP address types
fn classify_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

/// Classifies an IPv4 address
///
/// This function demonstrates bitwise operations and range checking
fn classify_ipv4(ip: &Ipv4Addr) -> String {
    let octets = ip.octets();

    // Check special ranges first
    if ip.is_loopback() {
        return "Loopback".to_string();
    }
    if ip.is_multicast() {
        return "Multicast".to_string();
    }
    if ip.is_broadcast() {
        return "Broadcast".to_string();
    }
    if ip.is_unspecified() {
        return "Unspecified".to_string();
    }
    if ip.is_link_local() {
        return "Link-Local".to_string();
    }

    // Check private ranges (RFC 1918)
    if octets[0] == 10 {
        return "Private (Class A - 10.0.0.0/8)".to_string();
    }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return "Private (Class B - 172.16.0.0/12)".to_string();
    }
    if octets[0] == 192 && octets[1] == 168 {
        return "Private (Class C - 192.168.0.0/16)".to_string();
    }

    // Check documentation ranges
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return "Documentation (TEST-NET-1)".to_string();
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return "Documentation (TEST-NET-2)".to_string();
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return "Documentation (TEST-NET-3)".to_string();
    }

    // Check CGNAT range
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return "Shared Address Space (CGNAT)".to_string();
    }

    // Check reserved ranges
    if octets[0] == 0 {
        return "Reserved (This Network)".to_string();
    }
    if octets[0] >= 240 {
        return "Reserved (Future Use)".to_string();
    }

    // Classify by class
    if octets[0] < 128 {
        "Public (Class A)".to_string()
    } else if octets[0] < 192 {
        "Public (Class B)".to_string()
    } else if octets[0] < 224 {
        "Public (Class C)".to_string()
    } else {
        "Public".to_string()
    }
}

/// Classifies an IPv6 address
fn classify_ipv6(ip: &Ipv6Addr) -> String {
    if ip.is_loopback() {
        return "Loopback (::1)".to_string();
    }
    if ip.is_multicast() {
        return "Multicast".to_string();
    }
    if ip.is_unspecified() {
        return "Unspecified (::)".to_string();
    }

    let segments = ip.segments();

    // Link-local
    if segments[0] & 0xffc0 == 0xfe80 {
        return "Link-Local".to_string();
    }

    // Site-local (deprecated)
    if segments[0] & 0xffc0 == 0xfec0 {
        return "Site-Local (Deprecated)".to_string();
    }

    // Unique Local (ULA) - similar to private IPv4
    if segments[0] & 0xfe00 == 0xfc00 {
        return "Unique Local Address (Private)".to_string();
    }

    // Documentation
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return "Documentation (2001:db8::/32)".to_string();
    }

    // 6to4
    if segments[0] == 0x2002 {
        return "6to4 Tunnel".to_string();
    }

    // Teredo
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return "Teredo Tunnel".to_string();
    }

    // Global unicast
    if segments[0] & 0xe000 == 0x2000 {
        return "Global Unicast".to_string();
    }

    "Unknown".to_string()
}

/// Checks if an IPv4 address is private
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}

/// Checks if an IPv6 address is private (ULA)
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] & 0xfe00 == 0xfc00
}

/// Checks if an IP is a documentation address
fn is_documentation(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

/// Converts IPv4 to binary representation
fn ipv4_to_binary(ip: &Ipv4Addr) -> String {
    ip.octets()
        .iter()
        .map(|octet| format!("{:08b}", octet))
        .collect::<Vec<_>>()
        .join(".")
}

/// Converts IPv4 to hex representation
fn ipv4_to_hex(ip: &Ipv4Addr) -> String {
    let octets = ip.octets();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        octets[0], octets[1], octets[2], octets[3]
    )
}

/// Generates reverse DNS format for an IP
fn to_reverse_dns(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let mut parts = Vec::new();
            for segment in v6.segments().iter().rev() {
                for i in 0..4 {
                    let nibble = (segment >> (i * 4)) & 0xf;
                    parts.push(format!("{:x}", nibble));
                }
            }
            format!("{}.ip6.arpa", parts.join("."))
        }
    }
}

/// Analyzes an IP address
fn analyze_ip(input: &str) -> IpAnalysis {
    let ip = match IpAddr::from_str(input) {
        Ok(ip) => ip,
        Err(e) => {
            return IpAnalysis {
                input: input.to_string(),
                valid: false,
                version: None,
                canonical: None,
                ip_type: None,
                is_private: false,
                is_loopback: false,
                is_multicast: false,
                is_link_local: false,
                is_documentation: false,
                binary: None,
                hex: None,
                reverse_dns: None,
                error: Some(e.to_string()),
            };
        }
    };

    let (version, binary, hex) = match ip {
        IpAddr::V4(v4) => (4, Some(ipv4_to_binary(&v4)), Some(ipv4_to_hex(&v4))),
        IpAddr::V6(_) => (6, None, None),
    };

    let is_private = match ip {
        IpAddr::V4(v4) => is_private_ipv4(&v4),
        IpAddr::V6(v6) => is_private_ipv6(&v6),
    };

    IpAnalysis {
        input: input.to_string(),
        valid: true,
        version: Some(version),
        canonical: Some(ip.to_string()),
        ip_type: Some(classify_ip(&ip)),
        is_private,
        is_loopback: ip.is_loopback(),
        is_multicast: ip.is_multicast(),
        is_link_local: match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        },
        is_documentation: is_documentation(&ip),
        binary,
        hex,
        reverse_dns: Some(to_reverse_dns(&ip)),
        error: None,
    }
}

/// Analyzes a CIDR network
fn analyze_cidr(input: &str) -> CidrAnalysis {
    let network = match IpNetwork::from_str(input) {
        Ok(net) => net,
        Err(e) => {
            return CidrAnalysis {
                input: input.to_string(),
                valid: false,
                network: None,
                broadcast: None,
                first_host: None,
                last_host: None,
                netmask: None,
                wildcard: None,
                prefix: None,
                total_addresses: None,
                usable_hosts: None,
                version: None,
                error: Some(e.to_string()),
            };
        }
    };

    match network {
        IpNetwork::V4(v4net) => analyze_cidr_v4(v4net, input),
        IpNetwork::V6(v6net) => analyze_cidr_v6(v6net, input),
    }
}

/// Analyzes an IPv4 CIDR network
fn analyze_cidr_v4(network: Ipv4Network, input: &str) -> CidrAnalysis {
    let prefix = network.prefix();
    let total = 2u128.pow(32 - prefix as u32);
    let usable = if prefix <= 30 { total - 2 } else { total };

    let network_addr = network.network();
    let broadcast = network.broadcast();

    // Calculate first and last usable host
    let first_host = if prefix <= 30 {
        let octets = network_addr.octets();
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] + 1).to_string())
    } else {
        Some(network_addr.to_string())
    };

    let last_host = if prefix <= 30 {
        let octets = broadcast.octets();
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] - 1).to_string())
    } else {
        Some(broadcast.to_string())
    };

    // Calculate wildcard mask
    let mask = network.mask();
    let wildcard_octets: Vec<u8> = mask.octets().iter().map(|o| !o).collect();
    let wildcard = format!(
        "{}.{}.{}.{}",
        wildcard_octets[0], wildcard_octets[1], wildcard_octets[2], wildcard_octets[3]
    );

    CidrAnalysis {
        input: input.to_string(),
        valid: true,
        network: Some(network_addr.to_string()),
        broadcast: Some(broadcast.to_string()),
        first_host,
        last_host,
        netmask: Some(mask.to_string()),
        wildcard: Some(wildcard),
        prefix: Some(prefix),
        total_addresses: Some(total),
        usable_hosts: Some(usable),
        version: Some(4),
        error: None,
    }
}

/// Analyzes an IPv6 CIDR network
fn analyze_cidr_v6(network: Ipv6Network, input: &str) -> CidrAnalysis {
    let prefix = network.prefix();
    let total = if prefix < 128 {
        2u128.pow(128 - prefix as u32)
    } else {
        1
    };

    CidrAnalysis {
        input: input.to_string(),
        valid: true,
        network: Some(network.network().to_string()),
        broadcast: None, // IPv6 doesn't have broadcast
        first_host: Some(network.network().to_string()),
        last_host: None, // Too large to calculate for most IPv6 ranges
        netmask: Some(network.mask().to_string()),
        wildcard: None,
        prefix: Some(prefix),
        total_addresses: Some(total),
        usable_hosts: Some(total),
        version: Some(6),
        error: None,
    }
}

/// Checks if an IP is contained in a CIDR range
fn check_contains(cidr: &str, ip: &str) -> Result<bool, IpError> {
    let network = IpNetwork::from_str(cidr)
        .map_err(|e| IpError::InvalidCidr(e.to_string()))?;
    let addr = IpAddr::from_str(ip)
        .map_err(|e| IpError::InvalidIp(e.to_string()))?;

    Ok(network.contains(addr))
}

/// Lists IPs in a CIDR range
fn list_ips(cidr: &str, limit: usize) -> Result<Vec<String>, IpError> {
    let network = IpNetwork::from_str(cidr)
        .map_err(|e| IpError::InvalidCidr(e.to_string()))?;

    match network {
        IpNetwork::V4(v4net) => {
            Ok(v4net.iter().take(limit).map(|ip| ip.to_string()).collect())
        }
        IpNetwork::V6(v6net) => {
            Ok(v6net.iter().take(limit).map(|ip| ip.to_string()).collect())
        }
    }
}

/// Prints IP analysis result
fn print_ip_analysis(analysis: &IpAnalysis) {
    if !analysis.valid {
        println!("{}: {}", "Invalid IP".red().bold(), analysis.error.as_ref().unwrap());
        return;
    }

    println!("{}", "IP Address Analysis".bold().green());
    println!("{}", "=".repeat(50).dimmed());
    println!("  Input:        {}", analysis.input.cyan());
    println!("  Canonical:    {}", analysis.canonical.as_ref().unwrap());
    println!("  Version:      IPv{}", analysis.version.unwrap());
    println!("  Type:         {}", analysis.ip_type.as_ref().unwrap().yellow());
    println!();
    println!("  Flags:");
    println!("    Private:      {}", format_bool(analysis.is_private));
    println!("    Loopback:     {}", format_bool(analysis.is_loopback));
    println!("    Multicast:    {}", format_bool(analysis.is_multicast));
    println!("    Link-Local:   {}", format_bool(analysis.is_link_local));
    println!("    Documentation:{}", format_bool(analysis.is_documentation));

    if let Some(ref binary) = analysis.binary {
        println!();
        println!("  Binary:       {}", binary);
    }
    if let Some(ref hex) = analysis.hex {
        println!("  Hexadecimal:  0x{}", hex);
    }
    if let Some(ref rdns) = analysis.reverse_dns {
        println!("  Reverse DNS:  {}", rdns.dimmed());
    }
}

/// Prints CIDR analysis result
fn print_cidr_analysis(analysis: &CidrAnalysis) {
    if !analysis.valid {
        println!("{}: {}", "Invalid CIDR".red().bold(), analysis.error.as_ref().unwrap());
        return;
    }

    println!("{}", "CIDR Network Analysis".bold().green());
    println!("{}", "=".repeat(50).dimmed());
    println!("  Input:          {}", analysis.input.cyan());
    println!("  Version:        IPv{}", analysis.version.unwrap());
    println!("  Prefix:         /{}", analysis.prefix.unwrap());
    println!();
    println!("  Addresses:");
    println!("    Network:      {}", analysis.network.as_ref().unwrap());
    if let Some(ref broadcast) = analysis.broadcast {
        println!("    Broadcast:    {}", broadcast);
    }
    if let Some(ref first) = analysis.first_host {
        println!("    First Host:   {}", first);
    }
    if let Some(ref last) = analysis.last_host {
        println!("    Last Host:    {}", last);
    }
    println!();
    println!("  Masks:");
    println!("    Netmask:      {}", analysis.netmask.as_ref().unwrap());
    if let Some(ref wildcard) = analysis.wildcard {
        println!("    Wildcard:     {}", wildcard);
    }
    println!();
    println!("  Size:");
    println!("    Total IPs:    {}", format_number(analysis.total_addresses.unwrap()));
    println!("    Usable Hosts: {}", format_number(analysis.usable_hosts.unwrap()));
}

/// Formats a boolean as colored string
fn format_bool(value: bool) -> String {
    if value {
        "Yes".green().to_string()
    } else {
        "No".dimmed().to_string()
    }
}

/// Formats a large number with commas
fn format_number(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }
    result
}

fn main() {
    let args = Args::parse();

    let result = match args.command {
        Commands::Validate { ip, json } => handle_validate(&ip, json),
        Commands::Cidr { cidr, json } => handle_cidr(&cidr, json),
        Commands::Contains { cidr, ip } => handle_contains(&cidr, &ip),
        Commands::List { cidr, limit } => handle_list(&cidr, limit),
        Commands::Bulk { input, json } => handle_bulk(&input, json),
        Commands::Compare { ip1, ip2 } => handle_compare(&ip1, &ip2),
        Commands::Private { ipv6 } => handle_private(ipv6),
    };

    if let Err(e) = result {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn handle_validate(ip: &str, json: bool) -> Result<(), IpError> {
    let analysis = analyze_ip(ip);

    if json {
        println!("{}", serde_json::to_string_pretty(&analysis).unwrap());
    } else {
        print_ip_analysis(&analysis);
    }

    Ok(())
}

fn handle_cidr(cidr: &str, json: bool) -> Result<(), IpError> {
    let analysis = analyze_cidr(cidr);

    if json {
        println!("{}", serde_json::to_string_pretty(&analysis).unwrap());
    } else {
        print_cidr_analysis(&analysis);
    }

    Ok(())
}

fn handle_contains(cidr: &str, ip: &str) -> Result<(), IpError> {
    let contained = check_contains(cidr, ip)?;

    println!("{}", "Network Containment Check".bold().green());
    println!("  Network: {}", cidr.cyan());
    println!("  IP:      {}", ip.cyan());
    println!("  Result:  {}",
        if contained {
            "YES - IP is in network".green().bold()
        } else {
            "NO - IP is not in network".red().bold()
        }
    );

    Ok(())
}

fn handle_list(cidr: &str, limit: usize) -> Result<(), IpError> {
    let ips = list_ips(cidr, limit)?;

    println!("{}", format!("IPs in {} (showing up to {})", cidr, limit).bold().green());
    println!("{}", "-".repeat(50).dimmed());

    for ip in &ips {
        println!("  {}", ip);
    }

    println!("{}", "-".repeat(50).dimmed());
    println!("Listed {} addresses", ips.len());

    Ok(())
}

fn handle_bulk(input: &str, json: bool) -> Result<(), IpError> {
    let ips: Vec<&str> = input.split(',').map(|s| s.trim()).collect();

    let analyses: Vec<IpAnalysis> = ips.iter().map(|ip| analyze_ip(ip)).collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&analyses).unwrap());
    } else {
        for analysis in &analyses {
            print_ip_analysis(analysis);
            println!();
        }
    }

    Ok(())
}

fn handle_compare(ip1: &str, ip2: &str) -> Result<(), IpError> {
    let a1 = analyze_ip(ip1);
    let a2 = analyze_ip(ip2);

    if !a1.valid {
        return Err(IpError::InvalidIp(ip1.to_string()));
    }
    if !a2.valid {
        return Err(IpError::InvalidIp(ip2.to_string()));
    }

    println!("{}", "IP Address Comparison".bold().green());
    println!("{}", "=".repeat(60).dimmed());
    println!("{:<20} {:<20} {:<20}", "", ip1.cyan(), ip2.cyan());
    println!("{:<20} {:<20} {:<20}", "Version:", format!("IPv{}", a1.version.unwrap()), format!("IPv{}", a2.version.unwrap()));
    println!("{:<20} {:<20} {:<20}", "Type:", a1.ip_type.unwrap_or_default(), a2.ip_type.unwrap_or_default());
    println!("{:<20} {:<20} {:<20}", "Private:", format_bool(a1.is_private), format_bool(a2.is_private));
    println!("{:<20} {:<20} {:<20}", "Loopback:", format_bool(a1.is_loopback), format_bool(a2.is_loopback));

    Ok(())
}

fn handle_private(include_ipv6: bool) -> Result<(), IpError> {
    println!("{}", "Private IP Address Ranges".bold().green());
    println!("{}", "=".repeat(60).dimmed());
    println!();
    println!("{}", "IPv4 Private Ranges (RFC 1918):".yellow());
    println!("  10.0.0.0/8       - Class A (16,777,216 addresses)");
    println!("  172.16.0.0/12    - Class B (1,048,576 addresses)");
    println!("  192.168.0.0/16   - Class C (65,536 addresses)");
    println!();
    println!("{}", "IPv4 Special Ranges:".yellow());
    println!("  127.0.0.0/8      - Loopback");
    println!("  169.254.0.0/16   - Link-Local (APIPA)");
    println!("  100.64.0.0/10    - Shared Address Space (CGNAT)");

    if include_ipv6 {
        println!();
        println!("{}", "IPv6 Private Ranges:".yellow());
        println!("  fc00::/7         - Unique Local Address (ULA)");
        println!("  fe80::/10        - Link-Local");
        println!();
        println!("{}", "IPv6 Special Ranges:".yellow());
        println!("  ::1/128          - Loopback");
        println!("  2001:db8::/32    - Documentation");
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        let analysis = analyze_ip("192.168.1.1");
        assert!(analysis.valid);
        assert_eq!(analysis.version, Some(4));
        assert!(analysis.is_private);
    }

    #[test]
    fn test_valid_ipv6() {
        let analysis = analyze_ip("::1");
        assert!(analysis.valid);
        assert_eq!(analysis.version, Some(6));
        assert!(analysis.is_loopback);
    }

    #[test]
    fn test_invalid_ip() {
        let analysis = analyze_ip("256.1.1.1");
        assert!(!analysis.valid);
        assert!(analysis.error.is_some());
    }

    #[test]
    fn test_private_ranges() {
        assert!(analyze_ip("10.0.0.1").is_private);
        assert!(analyze_ip("172.16.0.1").is_private);
        assert!(analyze_ip("192.168.0.1").is_private);
        assert!(!analyze_ip("8.8.8.8").is_private);
    }

    #[test]
    fn test_cidr_analysis() {
        let analysis = analyze_cidr("192.168.1.0/24");
        assert!(analysis.valid);
        assert_eq!(analysis.prefix, Some(24));
        assert_eq!(analysis.total_addresses, Some(256));
        assert_eq!(analysis.usable_hosts, Some(254));
    }

    #[test]
    fn test_contains() {
        assert!(check_contains("192.168.1.0/24", "192.168.1.100").unwrap());
        assert!(!check_contains("192.168.1.0/24", "192.168.2.1").unwrap());
    }

    #[test]
    fn test_list_ips() {
        let ips = list_ips("192.168.1.0/30", 10).unwrap();
        assert_eq!(ips.len(), 4);
        assert_eq!(ips[0], "192.168.1.0");
    }

    #[test]
    fn test_reverse_dns() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let rdns = to_reverse_dns(&ip);
        assert_eq!(rdns, "1.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_binary_conversion() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let binary = ipv4_to_binary(&ip);
        assert_eq!(binary, "11000000.10101000.00000001.00000001");
    }

    #[test]
    fn test_hex_conversion() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let hex = ipv4_to_hex(&ip);
        assert_eq!(hex, "c0a80101");
    }

    #[test]
    fn test_classify_documentation() {
        let ip = IpAddr::from_str("192.0.2.1").unwrap();
        assert!(is_documentation(&ip));

        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert!(!is_documentation(&ip));
    }
}
