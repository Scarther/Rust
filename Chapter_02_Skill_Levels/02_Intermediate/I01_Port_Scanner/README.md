# I01: Multi-threaded Port Scanner

## Overview

| Property | Value |
|----------|-------|
| **ID** | I01 |
| **Name** | Multi-threaded Port Scanner |
| **Difficulty** | Intermediate |
| **Time** | 1-2 hours |
| **Prerequisites** | B01-B15 completed |
| **MITRE ATT&CK** | T1046 - Network Service Scanning |

## What You'll Learn

1. TCP socket programming
2. Multi-threading with `std::thread`
3. Shared state with `Arc<Mutex<T>>`
4. Connection timeouts
5. Service banner grabbing
6. Rate limiting

---

## Security Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PORT SCANNING FUNDAMENTALS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TCP CONNECT SCAN (What we're building)                                     │
│  ══════════════════════════════════════                                     │
│                                                                              │
│  Client                Server                                                │
│    │                     │                                                   │
│    │──── SYN ──────────►│  "Hello, are you there?"                         │
│    │                     │                                                   │
│    │◄─── SYN/ACK ───────│  OPEN: "Yes, I'm listening!"                     │
│    │                     │   OR                                              │
│    │◄─── RST ───────────│  CLOSED: "Go away!"                              │
│    │                     │   OR                                              │
│    │     (timeout)       │  FILTERED: (silence)                             │
│    │                     │                                                   │
│    │──── ACK ──────────►│  Complete connection                             │
│    │                     │                                                   │
│                                                                              │
│  STEALTH SCANS (Future projects)                                            │
│  ═══════════════════════════════                                            │
│  SYN Scan  - Send SYN, don't complete handshake (requires raw sockets)     │
│  FIN Scan  - Send FIN to closed ports (OS fingerprinting)                   │
│  XMAS Scan - FIN+PSH+URG flags set                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Code

### Cargo.toml

```toml
[package]
name = "i01_port_scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
colored = "2.0"
```

### src/main.rs

```rust
use clap::Parser;
use colored::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// I01: Multi-threaded Port Scanner
#[derive(Parser, Debug)]
#[command(name = "portscan")]
#[command(version = "1.0.0")]
#[command(about = "Fast multi-threaded port scanner")]
struct Args {
    /// Target IP or hostname
    #[arg(short, long)]
    target: String,

    /// Port specification (e.g., 22,80,443 or 1-1000)
    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    /// Number of threads
    #[arg(long, default_value_t = 100)]
    threads: usize,

    /// Connection timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 1000)]
    timeout: u64,

    /// Grab service banners
    #[arg(short, long)]
    banner: bool,

    /// Show closed ports
    #[arg(long)]
    show_closed: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone)]
struct ScanResult {
    port: u16,
    status: PortStatus,
    service: Option<String>,
    banner: Option<String>,
    response_time: Duration,
}

/// Well-known ports and their services
fn get_service_name(port: u16) -> Option<&'static str> {
    let services: HashMap<u16, &'static str> = [
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (80, "http"),
        (110, "pop3"),
        (111, "rpcbind"),
        (135, "msrpc"),
        (139, "netbios-ssn"),
        (143, "imap"),
        (443, "https"),
        (445, "microsoft-ds"),
        (993, "imaps"),
        (995, "pop3s"),
        (1433, "mssql"),
        (1521, "oracle"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgresql"),
        (5900, "vnc"),
        (6379, "redis"),
        (8080, "http-proxy"),
        (8443, "https-alt"),
        (27017, "mongodb"),
    ].iter().cloned().collect();

    services.get(&port).copied()
}

/// Parse port specification
fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(format!("Invalid range: {}", part));
            }
            let start: u16 = range[0].parse().map_err(|_| format!("Invalid port: {}", range[0]))?;
            let end: u16 = range[1].parse().map_err(|_| format!("Invalid port: {}", range[1]))?;
            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    Ok(ports)
}

/// Attempt to grab banner from service
fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    // Set read timeout
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok()?;

    // Some services need a probe
    let probe = match port {
        80 | 8080 | 8443 => Some(b"HEAD / HTTP/1.0\r\n\r\n".to_vec()),
        _ => None,
    };

    if let Some(probe_data) = probe {
        stream.write_all(&probe_data).ok()?;
    }

    let mut buffer = [0u8; 1024];
    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n])
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();

            if !banner.is_empty() && banner.len() < 100 {
                Some(banner)
            } else if !banner.is_empty() {
                Some(format!("{}...", &banner[..50]))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Scan a single port
fn scan_port(addr: SocketAddr, timeout: Duration, grab_banners: bool) -> ScanResult {
    let start = Instant::now();

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let response_time = start.elapsed();

            let banner = if grab_banners {
                grab_banner(&mut stream, addr.port())
            } else {
                None
            };

            // Gracefully close
            let _ = stream.shutdown(Shutdown::Both);

            ScanResult {
                port: addr.port(),
                status: PortStatus::Open,
                service: get_service_name(addr.port()).map(String::from),
                banner,
                response_time,
            }
        }
        Err(e) => {
            let response_time = start.elapsed();
            let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                PortStatus::Filtered
            };

            ScanResult {
                port: addr.port(),
                status,
                service: None,
                banner: None,
                response_time,
            }
        }
    }
}

/// Resolve target to IP address
fn resolve_target(target: &str) -> Result<IpAddr, String> {
    // Try parsing as IP first
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try DNS resolution
    format!("{}:0", target)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| "No IP addresses found".to_string())
}

fn print_banner() {
    println!(r#"
{}
{}
{}
"#,
        "╔════════════════════════════════════════════════════════════╗".cyan(),
        "║              PORT SCANNER v1.0.0                           ║".cyan(),
        "╚════════════════════════════════════════════════════════════╝".cyan()
    );
}

fn main() {
    let args = Args::parse();

    print_banner();

    // Resolve target
    let ip = match resolve_target(&args.target) {
        Ok(ip) => {
            println!("{} Target: {} ({})", "[*]".blue(), args.target, ip);
            ip
        }
        Err(e) => {
            eprintln!("{} Error: {}", "[-]".red(), e);
            std::process::exit(1);
        }
    };

    // Parse ports
    let ports = match parse_ports(&args.ports) {
        Ok(p) => {
            println!("{} Scanning {} ports", "[*]".blue(), p.len());
            p
        }
        Err(e) => {
            eprintln!("{} Error: {}", "[-]".red(), e);
            std::process::exit(1);
        }
    };

    println!("{} Threads: {}", "[*]".blue(), args.threads);
    println!("{} Timeout: {}ms", "[*]".blue(), args.timeout);
    println!();

    let start_time = Instant::now();
    let timeout = Duration::from_millis(args.timeout);
    let results = Arc::new(Mutex::new(Vec::new()));
    let ports = Arc::new(ports);

    // Divide ports among threads
    let chunk_size = (ports.len() / args.threads).max(1);
    let mut handles = vec![];

    for chunk in ports.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let results = Arc::clone(&results);
        let grab_banners = args.banner;

        let handle = thread::spawn(move || {
            for port in chunk {
                let addr = SocketAddr::new(ip, port);
                let result = scan_port(addr, timeout, grab_banners);

                if matches!(result.status, PortStatus::Open) {
                    let mut results = results.lock().unwrap();
                    results.push(result);
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start_time.elapsed();

    // Sort and display results
    let mut results = results.lock().unwrap();
    results.sort_by_key(|r| r.port);

    println!("{}", "PORT      STATE    SERVICE          BANNER".bold());
    println!("{}", "─────────────────────────────────────────────────────────");

    for result in results.iter() {
        let port_str = format!("{}/tcp", result.port);
        let service = result.service.as_deref().unwrap_or("unknown");
        let banner = result.banner.as_deref().unwrap_or("");

        println!(
            "{:<9} {}    {:<16} {}",
            port_str,
            "open".green(),
            service,
            banner.dimmed()
        );
    }

    println!();
    println!(
        "{} Scan complete: {} open ports found in {:.2}s",
        "[+]".green(),
        results.len(),
        elapsed.as_secs_f64()
    );
    println!(
        "{} Scan rate: {:.0} ports/second",
        "[*]".blue(),
        ports.len() as f64 / elapsed.as_secs_f64()
    );
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
    fn test_service_lookup() {
        assert_eq!(get_service_name(22), Some("ssh"));
        assert_eq!(get_service_name(80), Some("http"));
        assert_eq!(get_service_name(12345), None);
    }
}
```

---

## Red Team Usage

### Reconnaissance Phase
```bash
# Quick scan of common ports
./portscan -t 192.168.1.1 -p 21,22,23,25,80,443,445,3389

# Full scan with banners
./portscan -t 10.0.0.5 -p 1-65535 --threads 500 --banner

# Scan multiple hosts (with bash loop)
for ip in $(cat targets.txt); do
    ./portscan -t $ip -p 1-1024 2>/dev/null | grep open
done
```

### OPSEC Considerations
- Use lower thread counts to avoid detection
- Randomize port order (exercise for you)
- Add delays between connections
- Consider source port manipulation (requires raw sockets)

---

## Blue Team Detection

### Network Detection
```yaml
# Suricata rule for port scan detection
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan"; \
    flags:S; threshold:type both,track by_src,count 100,seconds 60; \
    classtype:attempted-recon; sid:1000001; rev:1;)
```

### Windows Event Monitoring
```powershell
# Monitor for many failed connections (firewall logs)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=5157  # Windows Filtering Platform blocked connection
} | Where-Object {
    ($_.TimeCreated -gt (Get-Date).AddMinutes(-5))
} | Group-Object -Property { $_.Properties[3].Value } |
Where-Object { $_.Count -gt 50 }
```

---

## Exercises

1. **Add Port Randomization**: Randomize the order of port scanning
2. **Implement Rate Limiting**: Add a `--rate` flag to limit connections/second
3. **Add JSON Output**: Implement `-o json` for automation
4. **Service Version Detection**: Expand banner grabbing with protocol probes

---

[← Basic Level](../01_Basic/README.md) | [Next: I02 Network Enumeration →](../I02_Network_Enum/README.md)
