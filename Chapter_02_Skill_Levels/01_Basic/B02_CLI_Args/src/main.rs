//! # B02: Command-Line Arguments
//!
//! Comprehensive CLI parsing for security tools using clap.
//!
//! ## Usage
//! ```bash
//! cargo run -- -t 192.168.1.1 -p 22,80,443
//! cargo run -- --help
//! ```

use clap::Parser;
use std::net::IpAddr;

/// RustScan - A fast port scanner written in Rust
#[derive(Parser, Debug)]
#[command(name = "rustscan")]
#[command(author = "Security Student")]
#[command(version = "1.0.0")]
#[command(about = "A Rust-based network scanner")]
#[command(after_help = "EXAMPLES:
    rustscan -t 192.168.1.1 -p 22,80,443
    rustscan -t 10.0.0.0/24 -p 1-1000 --threads 200
    rustscan -t scanme.nmap.org -p common -o json")]
struct Args {
    /// Target IP address, hostname, or CIDR range
    #[arg(short, long, required = true)]
    target: String,

    /// Ports to scan (comma-separated, ranges, or 'common')
    #[arg(short, long, default_value = "common")]
    ports: String,

    /// Connection timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 1000)]
    timeout: u64,

    /// Number of concurrent threads
    #[arg(long, default_value_t = 100)]
    threads: usize,

    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Output format (text, json, csv, xml)
    #[arg(short, long, default_value = "text")]
    output: String,

    /// Output file path
    #[arg(short = 'O', long)]
    output_file: Option<String>,

    /// Disable banner
    #[arg(long, default_value_t = false)]
    no_banner: bool,
}

const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
];

fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    if port_str.to_lowercase() == "common" {
        return Ok(COMMON_PORTS.to_vec());
    }

    let mut ports = Vec::new();

    for part in port_str.split(',') {
        let part = part.trim();

        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }

            let start: u16 = bounds[0]
                .parse()
                .map_err(|_| format!("Invalid port: {}", bounds[0]))?;
            let end: u16 = bounds[1]
                .parse()
                .map_err(|_| format!("Invalid port: {}", bounds[1]))?;

            if start > end {
                return Err(format!("Invalid range: {} > {}", start, end));
            }

            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    ports.sort();
    ports.dedup();

    Ok(ports)
}

fn validate_target(target: &str) -> Result<(), String> {
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    if target.contains('/') {
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() == 2 && parts[0].parse::<IpAddr>().is_ok() {
            if let Ok(prefix) = parts[1].parse::<u8>() {
                if prefix <= 32 {
                    return Ok(());
                }
            }
        }
        return Err(format!("Invalid CIDR: {}", target));
    }

    if target.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Ok(());
    }

    Err(format!("Invalid target: {}", target))
}

fn print_banner() {
    println!(r#"
╔════════════════════════════════════════════════════════════╗
║                      RUSTSCAN v1.0.0                       ║
║              Fast Port Scanner in Rust                     ║
╚════════════════════════════════════════════════════════════╝
"#);
}

fn main() {
    let args = Args::parse();

    if !args.no_banner {
        print_banner();
    }

    if let Err(e) = validate_target(&args.target) {
        eprintln!("[!] Error: {}", e);
        std::process::exit(1);
    }

    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Error: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] Scan Configuration:");
    println!("    Target:     {}", args.target);
    println!("    Ports:      {} ports", ports.len());
    println!("    Timeout:    {}ms", args.timeout);
    println!("    Threads:    {}", args.threads);
    println!("    Output:     {}", args.output);
    println!();

    if args.verbose {
        println!("[+] Verbose mode enabled");
        println!("[*] Debug: {:?}", args);
    }

    println!("[*] B02 Complete! Proceed to B03: File Operations");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn test_parse_range() {
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_common() {
        let ports = parse_ports("common").unwrap();
        assert!(ports.contains(&22));
    }

    #[test]
    fn test_validate_ip() {
        assert!(validate_target("192.168.1.1").is_ok());
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_target("192.168.1.0/24").is_ok());
    }
}
