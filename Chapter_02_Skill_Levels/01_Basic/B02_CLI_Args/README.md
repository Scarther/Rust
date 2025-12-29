# B02: Command-Line Arguments

## Overview

| Property | Value |
|----------|-------|
| **ID** | B02 |
| **Name** | Command-Line Arguments |
| **Difficulty** | Basic |
| **Time** | 30 minutes |
| **Prerequisites** | B01 completed |

## What You'll Learn

1. Parsing command-line arguments
2. The `clap` crate for CLI parsing
3. Input validation
4. Argument types and defaults
5. Help generation

---

## The Code

### Cargo.toml

```toml
[package]
name = "b02_cli_args"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
```

### src/main.rs

```rust
use clap::Parser;
use std::net::IpAddr;

/// B02: Security Tool CLI Parser
/// Demonstrates comprehensive command-line argument handling
#[derive(Parser, Debug)]
#[command(name = "rustscan")]
#[command(author = "Security Student")]
#[command(version = "1.0.0")]
#[command(about = "A Rust-based network scanner", long_about = None)]
#[command(after_help = "EXAMPLES:
    rustscan -t 192.168.1.1 -p 22,80,443
    rustscan -t 10.0.0.0/24 -p 1-1000 --threads 200
    rustscan -t scanme.nmap.org -p 1-65535 -o json")]
struct Args {
    /// Target IP address, hostname, or CIDR range
    #[arg(short, long, required = true)]
    target: String,

    /// Ports to scan (comma-separated, ranges, or 'common')
    /// Examples: 22,80,443 or 1-1000 or common
    #[arg(short, long, default_value = "common")]
    ports: String,

    /// Connection timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..30000))]
    timeout: u64,

    /// Number of concurrent threads
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(usize).range(1..1000))]
    threads: usize,

    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json", "csv", "xml"])]
    output: String,

    /// Output file path (optional)
    #[arg(short = 'O', long)]
    output_file: Option<String>,

    /// Disable banner
    #[arg(long, default_value_t = false)]
    no_banner: bool,
}

/// Common ports for security scanning
const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
];

/// Parse port specification into list of ports
fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    // Handle 'common' keyword
    if port_str.to_lowercase() == "common" {
        return Ok(COMMON_PORTS.to_vec());
    }

    let mut ports = Vec::new();

    for part in port_str.split(',') {
        let part = part.trim();

        if part.contains('-') {
            // Range like "1-1000"
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }

            let start: u16 = bounds[0]
                .parse()
                .map_err(|_| format!("Invalid port number: {}", bounds[0]))?;
            let end: u16 = bounds[1]
                .parse()
                .map_err(|_| format!("Invalid port number: {}", bounds[1]))?;

            if start > end {
                return Err(format!("Invalid range: {} > {}", start, end));
            }

            if end - start > 10000 {
                return Err("Port range too large (max 10000 ports per range)".to_string());
            }

            ports.extend(start..=end);
        } else {
            // Single port
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    // Remove duplicates and sort
    ports.sort();
    ports.dedup();

    if ports.is_empty() {
        return Err("No ports specified".to_string());
    }

    Ok(ports)
}

/// Validate target specification
fn validate_target(target: &str) -> Result<(), String> {
    // Try parsing as IP address
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // Try parsing as CIDR (basic check)
    if target.contains('/') {
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() == 2 {
            if parts[0].parse::<IpAddr>().is_ok() {
                if let Ok(prefix) = parts[1].parse::<u8>() {
                    if prefix <= 32 {
                        return Ok(());
                    }
                }
            }
        }
        return Err(format!("Invalid CIDR notation: {}", target));
    }

    // Assume it's a hostname (basic validation)
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

    // Print banner unless disabled
    if !args.no_banner {
        print_banner();
    }

    // Validate target
    if let Err(e) = validate_target(&args.target) {
        eprintln!("[!] Error: {}", e);
        std::process::exit(1);
    }

    // Parse ports
    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Error: {}", e);
            std::process::exit(1);
        }
    };

    // Display configuration
    println!("[*] Scan Configuration:");
    println!("    Target:     {}", args.target);
    println!("    Ports:      {} ports", ports.len());
    if ports.len() <= 10 {
        println!("                {:?}", ports);
    } else {
        println!("                {} to {} (and {} more)",
            ports.first().unwrap(),
            ports.last().unwrap(),
            ports.len() - 2
        );
    }
    println!("    Timeout:    {}ms", args.timeout);
    println!("    Threads:    {}", args.threads);
    println!("    Output:     {}", args.output);
    if let Some(ref file) = args.output_file {
        println!("    File:       {}", file);
    }
    println!();

    if args.verbose {
        println!("[+] Verbose mode enabled");
        println!("[*] Debug: Args = {:?}", args);
        println!();
    }

    // Placeholder for actual scanning
    println!("[*] Ready to scan! (Actual scanning in later projects)");
    println!();
    println!("[*] B02 Complete! Proceed to B03: File Operations");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_multiple_ports() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_port_range() {
        let ports = parse_ports("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_common() {
        let ports = parse_ports("common").unwrap();
        assert!(ports.contains(&22));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn test_parse_mixed() {
        let ports = parse_ports("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_validate_ip() {
        assert!(validate_target("192.168.1.1").is_ok());
        assert!(validate_target("10.0.0.1").is_ok());
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_target("192.168.1.0/24").is_ok());
        assert!(validate_target("10.0.0.0/8").is_ok());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_target("scanme.nmap.org").is_ok());
        assert!(validate_target("localhost").is_ok());
    }

    #[test]
    fn test_invalid_port() {
        assert!(parse_ports("invalid").is_err());
        assert!(parse_ports("99999").is_err());
    }
}
```

---

## Clap Attribute Reference

| Attribute | Purpose | Example |
|-----------|---------|---------|
| `#[arg(short)]` | Single letter flag | `-v` |
| `#[arg(long)]` | Long form flag | `--verbose` |
| `#[arg(required)]` | Must be provided | Error if missing |
| `#[arg(default_value)]` | Default string | `default_value = "text"` |
| `#[arg(default_value_t)]` | Default typed | `default_value_t = 100` |
| `#[arg(value_parser)]` | Custom parser | Validate values |
| `#[command(about)]` | Tool description | Shown in help |
| `#[command(after_help)]` | Examples section | After main help |

---

## Red Team Perspective

### Argument Considerations
- Use common flag conventions (`-t`, `-p`, `-o`)
- Provide quiet mode for scripting
- Support multiple output formats for automation
- Consider OPSEC: avoid distinctive argument patterns

### Example Attack Chain
```bash
# Scan, parse JSON, chain to next tool
rustscan -t 192.168.1.0/24 -p common -o json | jq '.open_ports' | xargs -I {} nmap -sV {}
```

---

## Blue Team Perspective

### Detection Opportunities
- Command-line arguments logged via process creation auditing
- Distinctive patterns can be signatures
- Arguments may reveal attacker intent

### Windows Event Log Query
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
Where-Object { $_.Message -match 'rustscan' }
```

---

## Exercises

1. Add a `--stealth` flag that reduces thread count and adds random delays
2. Add support for reading targets from a file (`-iL targets.txt`)
3. Add a `--exclude-ports` option
4. Implement `--top-ports N` to scan top N most common ports

---

[← B01 Hello World](../B01_Hello_Security/README.md) | [Next: B03 File Operations →](../B03_File_Ops/README.md)
