# Case Study 03: Building a Red Team Tool

## Scenario

**Context:** Your security team needs a custom reconnaissance tool for authorized penetration testing engagements. Commercial tools leave too much of a footprint and are easily detected.

**Objective:** Build a stealthy, modular reconnaissance framework in Rust that can:
- Perform host discovery
- Scan ports with configurable timing
- Grab service banners
- Export findings in multiple formats

**Constraints:**
- Must be a single static binary
- Must have configurable rate limiting
- Must support multiple output formats
- Must be cross-platform (Linux primary, Windows secondary)

---

## Requirements Analysis

### Functional Requirements

| Feature | Priority | Notes |
|---------|----------|-------|
| Host discovery | High | ICMP + TCP probing |
| Port scanning | High | Connect scan, configurable ports |
| Banner grabbing | High | Service identification |
| Rate limiting | High | Stealth operations |
| Output formats | Medium | JSON, CSV, Markdown |
| Configuration file | Medium | Reusable scan profiles |
| Progress indication | Low | Visual feedback |

### Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Binary size | < 5 MB |
| Scan speed | 1000 ports/sec (configurable) |
| Memory usage | < 100 MB |
| Platform | Linux x86_64, Windows x86_64 |

---

## Design Decisions

### Architecture

```
┌────────────────────────────────────────────────────────┐
│                   ReconTool CLI                        │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │    Config    │  │    Scan      │  │   Output     │ │
│  │    Parser    │  │   Engine     │  │   Formatter  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                  │        │
│         └────────────┬────┴──────────────────┘        │
│                      │                                 │
│              ┌───────┴───────┐                        │
│              │  Rate Limiter │                        │
│              └───────────────┘                        │
│                                                        │
│  Modules:                                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │  Host   │ │  Port   │ │ Banner  │ │ Service │     │
│  │Discovery│ │ Scanner │ │ Grabber │ │ Detect  │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Async Runtime | Tokio | Mature, fast, well-documented |
| CLI | clap | Declarative, feature-rich |
| Rate Limiting | governor | Token bucket, flexible |
| Serialization | serde | De facto standard |
| Logging | tracing | Structured, async-friendly |

---

## Implementation

### Project Structure

```
recon_tool/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── host.rs
│   │   ├── port.rs
│   │   └── banner.rs
│   ├── output/
│   │   ├── mod.rs
│   │   ├── json.rs
│   │   ├── csv.rs
│   │   └── markdown.rs
│   └── utils/
│       ├── mod.rs
│       └── rate_limit.rs
```

### Cargo.toml

```toml
[package]
name = "recon_tool"
version = "1.0.0"
edition = "2021"

[dependencies]
tokio = { version = "1.34", features = ["full"] }
clap = { version = "4.4", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
governor = "0.6"
tracing = "0.1"
tracing-subscriber = "0.3"
ipnetwork = "0.20"
colored = "2.0"
indicatif = "0.17"
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1.0"

[profile.release]
opt-level = "z"
lto = true
strip = true
panic = "abort"
codegen-units = 1
```

### Main CLI (main.rs)

```rust
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod config;
mod output;
mod scanner;
mod utils;

use config::ScanConfig;
use scanner::{ScanResult, Scanner};

#[derive(Parser)]
#[command(name = "recon")]
#[command(about = "Reconnaissance tool for authorized security testing")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a single target
    Scan {
        /// Target IP or hostname
        #[arg(short, long)]
        target: String,

        /// Ports to scan (e.g., "22,80,443" or "1-1000")
        #[arg(short, long, default_value = "1-1024")]
        ports: String,

        /// Grab service banners
        #[arg(short, long)]
        banner: bool,

        /// Maximum requests per second
        #[arg(short = 'r', long, default_value = "100")]
        rate: u32,

        /// Connection timeout in milliseconds
        #[arg(short = 'T', long, default_value = "1000")]
        timeout: u64,
    },

    /// Discover hosts on a network
    Discover {
        /// Network in CIDR notation
        #[arg(short, long)]
        network: String,

        /// Discovery method (tcp, icmp)
        #[arg(short, long, default_value = "tcp")]
        method: String,
    },

    /// Scan multiple targets from file
    Batch {
        /// File containing targets (one per line)
        #[arg(short, long)]
        file: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Output format (json, csv, md)
        #[arg(short = 'F', long, default_value = "json")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    info!("ReconTool starting");

    match cli.command {
        Commands::Scan {
            target,
            ports,
            banner,
            rate,
            timeout,
        } => {
            let config = ScanConfig {
                targets: vec![target],
                ports: parse_ports(&ports)?,
                grab_banners: banner,
                rate_limit: rate,
                timeout_ms: timeout,
                ..Default::default()
            };

            let scanner = Scanner::new(config);
            let results = scanner.scan().await?;

            output::print_results(&results, "text")?;
        }

        Commands::Discover { network, method } => {
            info!("Discovering hosts on {}", network);
            let hosts = scanner::discover_hosts(&network, &method).await?;

            println!("\nLive hosts:");
            for host in hosts {
                println!("  {}", host);
            }
        }

        Commands::Batch { file, output, format } => {
            let targets = std::fs::read_to_string(&file)?
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .collect();

            let config = ScanConfig {
                targets,
                ..Default::default()
            };

            let scanner = Scanner::new(config);
            let results = scanner.scan().await?;

            output::write_results(&results, &output, &format)?;
            println!("Results written to {:?}", output);
        }
    }

    Ok(())
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            let start: u16 = range[0].parse()?;
            let end: u16 = range[1].parse()?;
            ports.extend(start..=end);
        } else {
            ports.push(part.parse()?);
        }
    }

    Ok(ports)
}
```

### Scanner Module (scanner/mod.rs)

```rust
use anyhow::Result;
use governor::{Quota, RateLimiter};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub mod banner;
pub mod host;
pub mod port;

use crate::config::ScanConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub target: String,
    pub ip: Option<String>,
    pub ports: Vec<PortResult>,
    pub scan_time: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub timestamp: String,
    pub hosts: Vec<HostResult>,
    pub total_time: f64,
    pub config_summary: String,
}

pub struct Scanner {
    config: ScanConfig,
    rate_limiter: Arc<RateLimiter<governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock>>,
    semaphore: Arc<Semaphore>,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(config.rate_limit).unwrap()
        );
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));

        Self {
            config,
            rate_limiter,
            semaphore,
        }
    }

    pub async fn scan(&self) -> Result<ScanResult> {
        let start_time = std::time::Instant::now();
        let mut host_results = Vec::new();

        info!("Starting scan of {} targets", self.config.targets.len());

        for target in &self.config.targets {
            info!("Scanning target: {}", target);
            let host_start = std::time::Instant::now();

            let mut port_results = Vec::new();

            for &port in &self.config.ports {
                // Rate limiting
                self.rate_limiter.until_ready().await;

                // Concurrency limiting
                let _permit = self.semaphore.acquire().await?;

                let result = self.scan_port(target, port).await;
                if let PortState::Open = result.state {
                    debug!("Found open port: {}:{}", target, port);
                }
                port_results.push(result);
            }

            // Filter to only open ports
            let open_ports: Vec<PortResult> = port_results
                .into_iter()
                .filter(|p| matches!(p.state, PortState::Open))
                .collect();

            host_results.push(HostResult {
                target: target.clone(),
                ip: resolve_ip(target).await,
                ports: open_ports,
                scan_time: host_start.elapsed().as_secs_f64(),
            });
        }

        let total_time = start_time.elapsed().as_secs_f64();

        Ok(ScanResult {
            timestamp: chrono::Utc::now().to_rfc3339(),
            hosts: host_results,
            total_time,
            config_summary: format!(
                "{} targets, {} ports, {}rps",
                self.config.targets.len(),
                self.config.ports.len(),
                self.config.rate_limit
            ),
        })
    }

    async fn scan_port(&self, target: &str, port: u16) -> PortResult {
        let addr = format!("{}:{}", target, port);

        let socket_addr: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(_) => {
                // Try DNS resolution
                match tokio::net::lookup_host(&addr).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => return PortResult {
                            port,
                            state: PortState::Filtered,
                            service: None,
                            banner: None,
                        },
                    },
                    Err(_) => return PortResult {
                        port,
                        state: PortState::Filtered,
                        service: None,
                        banner: None,
                    },
                }
            }
        };

        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
            Ok(Ok(mut stream)) => {
                let service = guess_service(port);

                let banner = if self.config.grab_banners {
                    banner::grab(&mut stream, port).await
                } else {
                    None
                };

                PortResult {
                    port,
                    state: PortState::Open,
                    service,
                    banner,
                }
            }
            Ok(Err(_)) => PortResult {
                port,
                state: PortState::Closed,
                service: None,
                banner: None,
            },
            Err(_) => PortResult {
                port,
                state: PortState::Filtered,
                service: None,
                banner: None,
            },
        }
    }
}

async fn resolve_ip(target: &str) -> Option<String> {
    if target.parse::<IpAddr>().is_ok() {
        return Some(target.to_string());
    }

    tokio::net::lookup_host(format!("{}:0", target))
        .await
        .ok()?
        .next()
        .map(|addr| addr.ip().to_string())
}

pub async fn discover_hosts(network: &str, method: &str) -> Result<Vec<String>> {
    let network: IpNetwork = network.parse()?;
    let mut live_hosts = Vec::new();

    let semaphore = Arc::new(Semaphore::new(100));
    let mut handles = Vec::new();

    for ip in network.iter() {
        let sem = semaphore.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let common_ports = [80, 443, 22, 445];
            for port in common_ports {
                let addr = SocketAddr::new(ip, port);
                if timeout(
                    Duration::from_millis(500),
                    TcpStream::connect(addr)
                ).await.is_ok() {
                    return Some(ip.to_string());
                }
            }
            None
        }));
    }

    for handle in handles {
        if let Ok(Some(ip)) = handle.await {
            live_hosts.push(ip);
        }
    }

    Ok(live_hosts)
}

fn guess_service(port: u16) -> Option<String> {
    match port {
        21 => Some("ftp".to_string()),
        22 => Some("ssh".to_string()),
        23 => Some("telnet".to_string()),
        25 => Some("smtp".to_string()),
        53 => Some("dns".to_string()),
        80 => Some("http".to_string()),
        443 => Some("https".to_string()),
        445 => Some("smb".to_string()),
        3306 => Some("mysql".to_string()),
        3389 => Some("rdp".to_string()),
        5432 => Some("postgresql".to_string()),
        8080 => Some("http-alt".to_string()),
        _ => None,
    }
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("1-10").unwrap();
        assert_eq!(ports.len(), 10);
    }

    #[test]
    fn test_parse_ports_list() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_guess_service() {
        assert_eq!(guess_service(22), Some("ssh".to_string()));
        assert_eq!(guess_service(80), Some("http".to_string()));
        assert_eq!(guess_service(12345), None);
    }
}
```

### Integration Tests

```rust
// tests/integration.rs
use assert_cmd::Command;

#[test]
fn test_scan_localhost() {
    let mut cmd = Command::cargo_bin("recon_tool").unwrap();
    cmd.args(["scan", "-t", "127.0.0.1", "-p", "22,80"])
        .assert()
        .success();
}
```

---

## Deployment

### Build Commands

```bash
# Linux static binary
cargo build --release --target x86_64-unknown-linux-musl

# Windows
cargo build --release --target x86_64-pc-windows-gnu

# Strip symbols for smaller binary
strip target/release/recon_tool
```

### Usage Examples

```bash
# Quick scan
./recon_tool scan -t 192.168.1.1 -p 1-1000

# With banner grabbing
./recon_tool scan -t target.com -p 22,80,443 --banner

# Network discovery
./recon_tool discover -n 192.168.1.0/24

# Batch scan with output
./recon_tool batch -f targets.txt -o results.json -F json
```

---

## Lessons Learned

### Technical Insights

1. **Rate limiting is crucial** - Without it, scans are detected immediately
2. **Async provides massive speedup** - 10x faster than synchronous
3. **Static binaries simplify deployment** - No dependency issues
4. **Configurable timeouts matter** - Different networks need different settings

### Operational Considerations

1. **Always get authorization** - Written permission before any scan
2. **Log your activities** - Timestamps and targets for accountability
3. **Rate limit by default** - Stealth should be the default mode
4. **Test in lab first** - Validate against known services

---

## MITRE ATT&CK Mapping

| Tool Feature | MITRE Technique |
|--------------|-----------------|
| Port scanning | T1046 - Network Service Discovery |
| Host discovery | T1018 - Remote System Discovery |
| Banner grabbing | T1046 - Network Service Discovery |
| Service detection | T1046 - Network Service Discovery |

---

## Legal and Ethical Notice

```
This tool is designed for AUTHORIZED security testing only.

Before using:
1. Obtain written permission from the target owner
2. Define scope clearly
3. Document all activities
4. Report findings responsibly

Unauthorized scanning is illegal in most jurisdictions.
```

---

[← CS02: Data Breach Hunt](./CS02_Data_Breach_Hunt.md) | [Back to Case Studies](./README.md) | [CS04: Enterprise Scanner →](./CS04_Enterprise_Scanner.md)
